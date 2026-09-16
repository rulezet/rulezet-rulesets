rule TTP_XOR_WriteProcessMemory_3c72 {
  strings:
    $key_3c72 = { 6b 00 [2] 59 22 [2] 5f 17 [2] 71 17 [2] 4e 0b }

  condition:
    any of them
}