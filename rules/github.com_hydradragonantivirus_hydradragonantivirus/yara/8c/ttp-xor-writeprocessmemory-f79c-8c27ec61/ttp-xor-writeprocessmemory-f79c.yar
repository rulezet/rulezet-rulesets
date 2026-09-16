rule TTP_XOR_WriteProcessMemory_f79c {
  strings:
    $key_f79c = { a0 ee [2] 92 cc [2] 94 f9 [2] ba f9 [2] 85 e5 }

  condition:
    any of them
}