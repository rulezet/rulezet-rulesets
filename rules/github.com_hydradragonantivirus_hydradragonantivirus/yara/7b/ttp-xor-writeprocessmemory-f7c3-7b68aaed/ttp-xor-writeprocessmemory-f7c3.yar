rule TTP_XOR_WriteProcessMemory_f7c3 {
  strings:
    $key_f7c3 = { a0 b1 [2] 92 93 [2] 94 a6 [2] ba a6 [2] 85 ba }

  condition:
    any of them
}