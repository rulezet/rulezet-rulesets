rule TTP_XOR_WriteProcessMemory_f737 {
  strings:
    $key_f737 = { a0 45 [2] 92 67 [2] 94 52 [2] ba 52 [2] 85 4e }

  condition:
    any of them
}