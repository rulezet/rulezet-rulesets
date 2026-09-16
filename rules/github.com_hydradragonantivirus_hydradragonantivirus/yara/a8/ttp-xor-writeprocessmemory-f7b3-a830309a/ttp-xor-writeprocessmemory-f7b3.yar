rule TTP_XOR_WriteProcessMemory_f7b3 {
  strings:
    $key_f7b3 = { a0 c1 [2] 92 e3 [2] 94 d6 [2] ba d6 [2] 85 ca }

  condition:
    any of them
}