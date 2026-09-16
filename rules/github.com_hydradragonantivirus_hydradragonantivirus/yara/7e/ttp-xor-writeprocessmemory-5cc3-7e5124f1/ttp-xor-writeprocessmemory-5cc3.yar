rule TTP_XOR_WriteProcessMemory_5cc3 {
  strings:
    $key_5cc3 = { 0b b1 [2] 39 93 [2] 3f a6 [2] 11 a6 [2] 2e ba }

  condition:
    any of them
}