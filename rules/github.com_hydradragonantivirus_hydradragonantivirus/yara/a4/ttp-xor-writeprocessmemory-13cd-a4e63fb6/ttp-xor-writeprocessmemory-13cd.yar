rule TTP_XOR_WriteProcessMemory_13cd {
  strings:
    $key_13cd = { 44 bf [2] 76 9d [2] 70 a8 [2] 5e a8 [2] 61 b4 }

  condition:
    any of them
}