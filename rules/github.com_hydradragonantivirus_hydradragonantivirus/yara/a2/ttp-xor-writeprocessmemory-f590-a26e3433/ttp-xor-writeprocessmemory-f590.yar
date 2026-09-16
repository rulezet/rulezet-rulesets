rule TTP_XOR_WriteProcessMemory_f590 {
  strings:
    $key_f590 = { a2 e2 [2] 90 c0 [2] 96 f5 [2] b8 f5 [2] 87 e9 }

  condition:
    any of them
}