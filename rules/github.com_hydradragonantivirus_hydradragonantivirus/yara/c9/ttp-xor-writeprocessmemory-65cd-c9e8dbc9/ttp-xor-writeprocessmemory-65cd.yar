rule TTP_XOR_WriteProcessMemory_65cd {
  strings:
    $key_65cd = { 32 bf [2] 00 9d [2] 06 a8 [2] 28 a8 [2] 17 b4 }

  condition:
    any of them
}