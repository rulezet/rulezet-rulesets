rule TTP_XOR_WriteProcessMemory_21cd {
  strings:
    $key_21cd = { 76 bf [2] 44 9d [2] 42 a8 [2] 6c a8 [2] 53 b4 }

  condition:
    any of them
}