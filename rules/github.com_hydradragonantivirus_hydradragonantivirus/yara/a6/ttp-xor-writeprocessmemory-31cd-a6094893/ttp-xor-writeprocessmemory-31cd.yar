rule TTP_XOR_WriteProcessMemory_31cd {
  strings:
    $key_31cd = { 66 bf [2] 54 9d [2] 52 a8 [2] 7c a8 [2] 43 b4 }

  condition:
    any of them
}