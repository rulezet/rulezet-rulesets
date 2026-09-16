rule TTP_XOR_WriteProcessMemory_f7a3 {
  strings:
    $key_f7a3 = { a0 d1 [2] 92 f3 [2] 94 c6 [2] ba c6 [2] 85 da }

  condition:
    any of them
}