rule TTP_XOR_WriteProcessMemory_f7c7 {
  strings:
    $key_f7c7 = { a0 b5 [2] 92 97 [2] 94 a2 [2] ba a2 [2] 85 be }

  condition:
    any of them
}