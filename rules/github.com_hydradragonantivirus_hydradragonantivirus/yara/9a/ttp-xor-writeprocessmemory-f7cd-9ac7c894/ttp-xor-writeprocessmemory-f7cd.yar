rule TTP_XOR_WriteProcessMemory_f7cd {
  strings:
    $key_f7cd = { a0 bf [2] 92 9d [2] 94 a8 [2] ba a8 [2] 85 b4 }

  condition:
    any of them
}