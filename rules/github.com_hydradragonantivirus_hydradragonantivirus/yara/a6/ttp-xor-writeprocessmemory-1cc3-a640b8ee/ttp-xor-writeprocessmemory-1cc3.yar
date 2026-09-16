rule TTP_XOR_WriteProcessMemory_1cc3 {
  strings:
    $key_1cc3 = { 4b b1 [2] 79 93 [2] 7f a6 [2] 51 a6 [2] 6e ba }

  condition:
    any of them
}