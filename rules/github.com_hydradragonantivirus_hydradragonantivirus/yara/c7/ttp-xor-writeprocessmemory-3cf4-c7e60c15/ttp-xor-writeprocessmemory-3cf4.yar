rule TTP_XOR_WriteProcessMemory_3cf4 {
  strings:
    $key_3cf4 = { 6b 86 [2] 59 a4 [2] 5f 91 [2] 71 91 [2] 4e 8d }

  condition:
    any of them
}