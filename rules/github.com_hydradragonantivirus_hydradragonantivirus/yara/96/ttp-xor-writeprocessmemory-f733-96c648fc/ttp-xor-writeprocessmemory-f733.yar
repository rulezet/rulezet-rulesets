rule TTP_XOR_WriteProcessMemory_f733 {
  strings:
    $key_f733 = { a0 41 [2] 92 63 [2] 94 56 [2] ba 56 [2] 85 4a }

  condition:
    any of them
}