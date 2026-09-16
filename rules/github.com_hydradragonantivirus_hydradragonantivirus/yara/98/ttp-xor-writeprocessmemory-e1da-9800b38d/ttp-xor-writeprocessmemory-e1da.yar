rule TTP_XOR_WriteProcessMemory_e1da {
  strings:
    $key_e1da = { b6 a8 [2] 84 8a [2] 82 bf [2] ac bf [2] 93 a3 }

  condition:
    any of them
}