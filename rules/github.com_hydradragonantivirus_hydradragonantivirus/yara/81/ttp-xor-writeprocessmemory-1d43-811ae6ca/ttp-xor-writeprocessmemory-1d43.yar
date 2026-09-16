rule TTP_XOR_WriteProcessMemory_1d43 {
  strings:
    $key_1d43 = { 4a 31 [2] 78 13 [2] 7e 26 [2] 50 26 [2] 6f 3a }

  condition:
    any of them
}