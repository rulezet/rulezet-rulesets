rule TTP_XOR_WriteProcessMemory_f762 {
  strings:
    $key_f762 = { a0 10 [2] 92 32 [2] 94 07 [2] ba 07 [2] 85 1b }

  condition:
    any of them
}