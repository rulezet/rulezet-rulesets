rule TTP_XOR_WriteProcessMemory_e1cd {
  strings:
    $key_e1cd = { b6 bf [2] 84 9d [2] 82 a8 [2] ac a8 [2] 93 b4 }

  condition:
    any of them
}