rule TTP_XOR_WriteProcessMemory_6fc3 {
  strings:
    $key_6fc3 = { 38 b1 [2] 0a 93 [2] 0c a6 [2] 22 a6 [2] 1d ba }

  condition:
    any of them
}