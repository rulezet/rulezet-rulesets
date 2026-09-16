rule TTP_XOR_WriteProcessMemory_e0cd {
  strings:
    $key_e0cd = { b7 bf [2] 85 9d [2] 83 a8 [2] ad a8 [2] 92 b4 }

  condition:
    any of them
}