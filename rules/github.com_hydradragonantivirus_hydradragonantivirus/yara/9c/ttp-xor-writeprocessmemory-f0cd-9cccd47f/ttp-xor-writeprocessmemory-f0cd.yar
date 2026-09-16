rule TTP_XOR_WriteProcessMemory_f0cd {
  strings:
    $key_f0cd = { a7 bf [2] 95 9d [2] 93 a8 [2] bd a8 [2] 82 b4 }

  condition:
    any of them
}