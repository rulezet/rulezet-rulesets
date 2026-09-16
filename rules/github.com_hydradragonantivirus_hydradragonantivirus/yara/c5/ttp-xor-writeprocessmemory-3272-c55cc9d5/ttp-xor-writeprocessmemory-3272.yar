rule TTP_XOR_WriteProcessMemory_3272 {
  strings:
    $key_3272 = { 65 00 [2] 57 22 [2] 51 17 [2] 7f 17 [2] 40 0b }

  condition:
    any of them
}