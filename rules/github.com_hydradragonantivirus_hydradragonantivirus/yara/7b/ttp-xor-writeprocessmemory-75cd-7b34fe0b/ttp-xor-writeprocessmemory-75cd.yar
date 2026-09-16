rule TTP_XOR_WriteProcessMemory_75cd {
  strings:
    $key_75cd = { 22 bf [2] 10 9d [2] 16 a8 [2] 38 a8 [2] 07 b4 }

  condition:
    any of them
}