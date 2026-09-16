rule TTP_XOR_WriteProcessMemory_12c3 {
  strings:
    $key_12c3 = { 45 b1 [2] 77 93 [2] 71 a6 [2] 5f a6 [2] 60 ba }

  condition:
    any of them
}