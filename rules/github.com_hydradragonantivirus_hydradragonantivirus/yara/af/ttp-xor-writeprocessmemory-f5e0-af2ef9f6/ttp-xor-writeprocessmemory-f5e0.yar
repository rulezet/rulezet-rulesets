rule TTP_XOR_WriteProcessMemory_f5e0 {
  strings:
    $key_f5e0 = { a2 92 [2] 90 b0 [2] 96 85 [2] b8 85 [2] 87 99 }

  condition:
    any of them
}