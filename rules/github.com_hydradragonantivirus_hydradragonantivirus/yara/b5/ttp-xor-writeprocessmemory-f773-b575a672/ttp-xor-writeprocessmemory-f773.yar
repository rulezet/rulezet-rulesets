rule TTP_XOR_WriteProcessMemory_f773 {
  strings:
    $key_f773 = { a0 01 [2] 92 23 [2] 94 16 [2] ba 16 [2] 85 0a }

  condition:
    any of them
}