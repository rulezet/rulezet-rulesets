rule TTP_XOR_WriteProcessMemory_5fcd {
  strings:
    $key_5fcd = { 08 bf [2] 3a 9d [2] 3c a8 [2] 12 a8 [2] 2d b4 }

  condition:
    any of them
}