rule TTP_XOR_WriteProcessMemory_1363 {
  strings:
    $key_1363 = { 44 11 [2] 76 33 [2] 70 06 [2] 5e 06 [2] 61 1a }

  condition:
    any of them
}