rule TTP_XOR_WriteProcessMemory_79d7 {
  strings:
    $key_79d7 = { 2e a5 [2] 1c 87 [2] 1a b2 [2] 34 b2 [2] 0b ae }

  condition:
    any of them
}