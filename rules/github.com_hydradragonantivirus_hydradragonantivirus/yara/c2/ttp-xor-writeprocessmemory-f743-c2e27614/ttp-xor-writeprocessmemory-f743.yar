rule TTP_XOR_WriteProcessMemory_f743 {
  strings:
    $key_f743 = { a0 31 [2] 92 13 [2] 94 26 [2] ba 26 [2] 85 3a }

  condition:
    any of them
}