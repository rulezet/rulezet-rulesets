rule TTP_XOR_WriteProcessMemory_f5a0 {
  strings:
    $key_f5a0 = { a2 d2 [2] 90 f0 [2] 96 c5 [2] b8 c5 [2] 87 d9 }

  condition:
    any of them
}