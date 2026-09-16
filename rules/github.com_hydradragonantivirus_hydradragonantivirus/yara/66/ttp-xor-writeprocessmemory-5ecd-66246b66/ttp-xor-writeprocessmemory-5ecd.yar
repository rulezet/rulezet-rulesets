rule TTP_XOR_WriteProcessMemory_5ecd {
  strings:
    $key_5ecd = { 09 bf [2] 3b 9d [2] 3d a8 [2] 13 a8 [2] 2c b4 }

  condition:
    any of them
}