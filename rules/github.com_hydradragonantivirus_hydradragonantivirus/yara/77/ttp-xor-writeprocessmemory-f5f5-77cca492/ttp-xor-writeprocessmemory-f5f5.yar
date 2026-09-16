rule TTP_XOR_WriteProcessMemory_f5f5 {
  strings:
    $key_f5f5 = { a2 87 [2] 90 a5 [2] 96 90 [2] b8 90 [2] 87 8c }

  condition:
    any of them
}