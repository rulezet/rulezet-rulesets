rule TTP_XOR_WriteProcessMemory_57d7 {
  strings:
    $key_57d7 = { 00 a5 [2] 32 87 [2] 34 b2 [2] 1a b2 [2] 25 ae }

  condition:
    any of them
}