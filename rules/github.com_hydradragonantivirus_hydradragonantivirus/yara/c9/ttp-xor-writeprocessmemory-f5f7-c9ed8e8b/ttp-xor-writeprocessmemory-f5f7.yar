rule TTP_XOR_WriteProcessMemory_f5f7 {
  strings:
    $key_f5f7 = { a2 85 [2] 90 a7 [2] 96 92 [2] b8 92 [2] 87 8e }

  condition:
    any of them
}