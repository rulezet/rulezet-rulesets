rule TTP_XOR_WriteProcessMemory_f703 {
  strings:
    $key_f703 = { a0 71 [2] 92 53 [2] 94 66 [2] ba 66 [2] 85 7a }

  condition:
    any of them
}