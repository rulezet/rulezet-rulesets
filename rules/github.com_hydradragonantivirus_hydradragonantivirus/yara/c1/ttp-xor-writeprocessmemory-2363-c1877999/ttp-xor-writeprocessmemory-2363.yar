rule TTP_XOR_WriteProcessMemory_2363 {
  strings:
    $key_2363 = { 74 11 [2] 46 33 [2] 40 06 [2] 6e 06 [2] 51 1a }

  condition:
    any of them
}