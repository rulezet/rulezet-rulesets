rule TTP_XOR_WriteProcessMemory_4526 {
  strings:
    $key_4526 = { 12 54 [2] 20 76 [2] 26 43 [2] 08 43 [2] 37 5f }

  condition:
    any of them
}