rule TTP_XOR_WriteProcessMemory_6cc3 {
  strings:
    $key_6cc3 = { 3b b1 [2] 09 93 [2] 0f a6 [2] 21 a6 [2] 1e ba }

  condition:
    any of them
}