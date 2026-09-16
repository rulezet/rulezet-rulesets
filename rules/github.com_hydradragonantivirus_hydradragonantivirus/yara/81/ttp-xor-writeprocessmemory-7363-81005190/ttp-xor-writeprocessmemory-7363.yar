rule TTP_XOR_WriteProcessMemory_7363 {
  strings:
    $key_7363 = { 24 11 [2] 16 33 [2] 10 06 [2] 3e 06 [2] 01 1a }

  condition:
    any of them
}