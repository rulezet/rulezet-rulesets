rule TTP_XOR_WriteProcessMemory_7ed5 {
  strings:
    $key_7ed5 = { 29 a7 [2] 1b 85 [2] 1d b0 [2] 33 b0 [2] 0c ac }

  condition:
    any of them
}