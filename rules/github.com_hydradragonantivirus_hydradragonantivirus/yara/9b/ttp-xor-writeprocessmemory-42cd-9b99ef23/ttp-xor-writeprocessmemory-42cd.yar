rule TTP_XOR_WriteProcessMemory_42cd {
  strings:
    $key_42cd = { 15 bf [2] 27 9d [2] 21 a8 [2] 0f a8 [2] 30 b4 }

  condition:
    any of them
}