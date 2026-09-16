rule TTP_XOR_WriteProcessMemory_27cd {
  strings:
    $key_27cd = { 70 bf [2] 42 9d [2] 44 a8 [2] 6a a8 [2] 55 b4 }

  condition:
    any of them
}