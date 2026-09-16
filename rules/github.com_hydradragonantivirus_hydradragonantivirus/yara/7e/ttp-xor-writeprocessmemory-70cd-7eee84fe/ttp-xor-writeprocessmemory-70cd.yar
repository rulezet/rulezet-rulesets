rule TTP_XOR_WriteProcessMemory_70cd {
  strings:
    $key_70cd = { 27 bf [2] 15 9d [2] 13 a8 [2] 3d a8 [2] 02 b4 }

  condition:
    any of them
}