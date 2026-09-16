rule TTP_XOR_WriteProcessMemory_45cd {
  strings:
    $key_45cd = { 12 bf [2] 20 9d [2] 26 a8 [2] 08 a8 [2] 37 b4 }

  condition:
    any of them
}