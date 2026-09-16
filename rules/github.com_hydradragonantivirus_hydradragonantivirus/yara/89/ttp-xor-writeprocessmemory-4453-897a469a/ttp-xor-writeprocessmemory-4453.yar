rule TTP_XOR_WriteProcessMemory_4453 {
  strings:
    $key_4453 = { 13 21 [2] 21 03 [2] 27 36 [2] 09 36 [2] 36 2a }

  condition:
    any of them
}