rule TTP_XOR_WriteProcessMemory_36cd {
  strings:
    $key_36cd = { 61 bf [2] 53 9d [2] 55 a8 [2] 7b a8 [2] 44 b4 }

  condition:
    any of them
}