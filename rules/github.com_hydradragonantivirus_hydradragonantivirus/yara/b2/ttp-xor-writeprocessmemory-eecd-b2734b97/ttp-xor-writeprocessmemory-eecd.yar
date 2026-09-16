rule TTP_XOR_WriteProcessMemory_eecd {
  strings:
    $key_eecd = { b9 bf [2] 8b 9d [2] 8d a8 [2] a3 a8 [2] 9c b4 }

  condition:
    any of them
}