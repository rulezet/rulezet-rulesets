rule TTP_XOR_WriteProcessMemory_52c3 {
  strings:
    $key_52c3 = { 05 b1 [2] 37 93 [2] 31 a6 [2] 1f a6 [2] 20 ba }

  condition:
    any of them
}