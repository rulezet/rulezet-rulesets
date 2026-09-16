rule TTP_XOR_WriteProcessMemory_4863 {
  strings:
    $key_4863 = { 1f 11 [2] 2d 33 [2] 2b 06 [2] 05 06 [2] 3a 1a }

  condition:
    any of them
}