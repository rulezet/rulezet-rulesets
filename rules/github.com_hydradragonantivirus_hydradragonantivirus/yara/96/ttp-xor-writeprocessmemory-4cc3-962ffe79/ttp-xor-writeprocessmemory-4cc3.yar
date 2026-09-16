rule TTP_XOR_WriteProcessMemory_4cc3 {
  strings:
    $key_4cc3 = { 1b b1 [2] 29 93 [2] 2f a6 [2] 01 a6 [2] 3e ba }

  condition:
    any of them
}