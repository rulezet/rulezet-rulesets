rule TTP_XOR_WriteProcessMemory_f764 {
  strings:
    $key_f764 = { a0 16 [2] 92 34 [2] 94 01 [2] ba 01 [2] 85 1d }

  condition:
    any of them
}