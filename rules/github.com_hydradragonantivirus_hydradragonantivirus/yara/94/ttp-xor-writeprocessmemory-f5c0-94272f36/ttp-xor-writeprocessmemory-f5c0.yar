rule TTP_XOR_WriteProcessMemory_f5c0 {
  strings:
    $key_f5c0 = { a2 b2 [2] 90 90 [2] 96 a5 [2] b8 a5 [2] 87 b9 }

  condition:
    any of them
}