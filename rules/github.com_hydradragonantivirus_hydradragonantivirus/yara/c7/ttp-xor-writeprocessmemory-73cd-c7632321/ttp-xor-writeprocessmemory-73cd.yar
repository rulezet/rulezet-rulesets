rule TTP_XOR_WriteProcessMemory_73cd {
  strings:
    $key_73cd = { 24 bf [2] 16 9d [2] 10 a8 [2] 3e a8 [2] 01 b4 }

  condition:
    any of them
}