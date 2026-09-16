rule TTP_XOR_WriteProcessMemory_7bd7 {
  strings:
    $key_7bd7 = { 2c a5 [2] 1e 87 [2] 18 b2 [2] 36 b2 [2] 09 ae }

  condition:
    any of them
}