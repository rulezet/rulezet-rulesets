rule TTP_XOR_WriteProcessMemory_0463 {
  strings:
    $key_0463 = { 53 11 [2] 61 33 [2] 67 06 [2] 49 06 [2] 76 1a }

  condition:
    any of them
}