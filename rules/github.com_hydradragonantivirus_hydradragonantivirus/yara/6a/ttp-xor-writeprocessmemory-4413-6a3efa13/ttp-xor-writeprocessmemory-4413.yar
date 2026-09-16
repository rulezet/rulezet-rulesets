rule TTP_XOR_WriteProcessMemory_4413 {
  strings:
    $key_4413 = { 13 61 [2] 21 43 [2] 27 76 [2] 09 76 [2] 36 6a }

  condition:
    any of them
}