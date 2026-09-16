rule TTP_XOR_WriteProcessMemory_6336 {
  strings:
    $key_6336 = { 34 44 [2] 06 66 [2] 00 53 [2] 2e 53 [2] 11 4f }

  condition:
    any of them
}