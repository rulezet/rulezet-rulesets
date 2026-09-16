rule TTP_XOR_WriteProcessMemory_35cd {
  strings:
    $key_35cd = { 62 bf [2] 50 9d [2] 56 a8 [2] 78 a8 [2] 47 b4 }

  condition:
    any of them
}