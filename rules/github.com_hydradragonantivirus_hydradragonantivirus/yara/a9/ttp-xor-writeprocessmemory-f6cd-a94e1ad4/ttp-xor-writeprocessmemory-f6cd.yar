rule TTP_XOR_WriteProcessMemory_f6cd {
  strings:
    $key_f6cd = { a1 bf [2] 93 9d [2] 95 a8 [2] bb a8 [2] 84 b4 }

  condition:
    any of them
}