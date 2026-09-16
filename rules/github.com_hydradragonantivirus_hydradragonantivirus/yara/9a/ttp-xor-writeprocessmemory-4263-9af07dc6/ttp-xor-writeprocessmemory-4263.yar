rule TTP_XOR_WriteProcessMemory_4263 {
  strings:
    $key_4263 = { 15 11 [2] 27 33 [2] 21 06 [2] 0f 06 [2] 30 1a }

  condition:
    any of them
}