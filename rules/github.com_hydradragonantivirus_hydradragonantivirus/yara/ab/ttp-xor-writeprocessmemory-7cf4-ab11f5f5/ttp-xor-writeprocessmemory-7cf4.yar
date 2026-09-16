rule TTP_XOR_WriteProcessMemory_7cf4 {
  strings:
    $key_7cf4 = { 2b 86 [2] 19 a4 [2] 1f 91 [2] 31 91 [2] 0e 8d }

  condition:
    any of them
}