rule TTP_XOR_WriteProcessMemory_22cd {
  strings:
    $key_22cd = { 75 bf [2] 47 9d [2] 41 a8 [2] 6f a8 [2] 50 b4 }

  condition:
    any of them
}