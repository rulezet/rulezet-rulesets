rule TTP_XOR_WriteProcessMemory_2fcd {
  strings:
    $key_2fcd = { 78 bf [2] 4a 9d [2] 4c a8 [2] 62 a8 [2] 5d b4 }

  condition:
    any of them
}