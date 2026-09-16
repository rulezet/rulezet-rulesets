rule TTP_XOR_WriteProcessMemory_0ecd {
  strings:
    $key_0ecd = { 59 bf [2] 6b 9d [2] 6d a8 [2] 43 a8 [2] 7c b4 }

  condition:
    any of them
}