rule TTP_XOR_WriteProcessMemory_69d7 {
  strings:
    $key_69d7 = { 3e a5 [2] 0c 87 [2] 0a b2 [2] 24 b2 [2] 1b ae }

  condition:
    any of them
}