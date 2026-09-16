rule TTP_XOR_WriteProcessMemory_51cd {
  strings:
    $key_51cd = { 06 bf [2] 34 9d [2] 32 a8 [2] 1c a8 [2] 23 b4 }

  condition:
    any of them
}