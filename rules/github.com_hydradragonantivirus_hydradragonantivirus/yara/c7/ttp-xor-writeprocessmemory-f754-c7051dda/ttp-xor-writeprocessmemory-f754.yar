rule TTP_XOR_WriteProcessMemory_f754 {
  strings:
    $key_f754 = { a0 26 [2] 92 04 [2] 94 31 [2] ba 31 [2] 85 2d }

  condition:
    any of them
}