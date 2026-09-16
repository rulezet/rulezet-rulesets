rule TTP_XOR_WriteProcessMemory_f5e2 {
  strings:
    $key_f5e2 = { a2 90 [2] 90 b2 [2] 96 87 [2] b8 87 [2] 87 9b }

  condition:
    any of them
}