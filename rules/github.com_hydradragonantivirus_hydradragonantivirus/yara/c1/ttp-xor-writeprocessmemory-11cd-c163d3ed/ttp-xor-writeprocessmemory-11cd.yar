rule TTP_XOR_WriteProcessMemory_11cd {
  strings:
    $key_11cd = { 46 bf [2] 74 9d [2] 72 a8 [2] 5c a8 [2] 63 b4 }

  condition:
    any of them
}