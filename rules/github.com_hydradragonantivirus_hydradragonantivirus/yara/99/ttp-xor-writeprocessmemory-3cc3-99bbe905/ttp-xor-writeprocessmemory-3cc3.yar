rule TTP_XOR_WriteProcessMemory_3cc3 {
  strings:
    $key_3cc3 = { 6b b1 [2] 59 93 [2] 5f a6 [2] 71 a6 [2] 4e ba }

  condition:
    any of them
}