rule TTP_XOR_WriteProcessMemory_2cf4 {
  strings:
    $key_2cf4 = { 7b 86 [2] 49 a4 [2] 4f 91 [2] 61 91 [2] 5e 8d }

  condition:
    any of them
}