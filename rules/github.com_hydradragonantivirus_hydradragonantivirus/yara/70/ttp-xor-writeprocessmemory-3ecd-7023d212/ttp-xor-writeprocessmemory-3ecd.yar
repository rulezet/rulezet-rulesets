rule TTP_XOR_WriteProcessMemory_3ecd {
  strings:
    $key_3ecd = { 69 bf [2] 5b 9d [2] 5d a8 [2] 73 a8 [2] 4c b4 }

  condition:
    any of them
}