rule TTP_XOR_WriteProcessMemory_e5cd {
  strings:
    $key_e5cd = { b2 bf [2] 80 9d [2] 86 a8 [2] a8 a8 [2] 97 b4 }

  condition:
    any of them
}