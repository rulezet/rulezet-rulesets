rule TTP_XOR_WriteProcessMemory_1d13 {
  strings:
    $key_1d13 = { 4a 61 [2] 78 43 [2] 7e 76 [2] 50 76 [2] 6f 6a }

  condition:
    any of them
}