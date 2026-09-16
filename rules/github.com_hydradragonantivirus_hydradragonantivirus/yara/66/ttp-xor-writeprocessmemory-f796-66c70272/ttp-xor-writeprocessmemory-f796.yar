rule TTP_XOR_WriteProcessMemory_f796 {
  strings:
    $key_f796 = { a0 e4 [2] 92 c6 [2] 94 f3 [2] ba f3 [2] 85 ef }

  condition:
    any of them
}