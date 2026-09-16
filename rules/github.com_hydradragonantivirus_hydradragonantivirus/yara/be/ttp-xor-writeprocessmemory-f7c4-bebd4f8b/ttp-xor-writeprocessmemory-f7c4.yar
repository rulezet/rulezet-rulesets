rule TTP_XOR_WriteProcessMemory_f7c4 {
  strings:
    $key_f7c4 = { a0 b6 [2] 92 94 [2] 94 a1 [2] ba a1 [2] 85 bd }

  condition:
    any of them
}