rule TTP_XOR_WriteProcessMemory_4ecd {
  strings:
    $key_4ecd = { 19 bf [2] 2b 9d [2] 2d a8 [2] 03 a8 [2] 3c b4 }

  condition:
    any of them
}