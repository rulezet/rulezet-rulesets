rule TTP_XOR_WriteProcessMemory_a6d7 {
  strings:
    $key_a6d7 = { f1 a5 [2] c3 87 [2] c5 b2 [2] eb b2 [2] d4 ae }

  condition:
    any of them
}