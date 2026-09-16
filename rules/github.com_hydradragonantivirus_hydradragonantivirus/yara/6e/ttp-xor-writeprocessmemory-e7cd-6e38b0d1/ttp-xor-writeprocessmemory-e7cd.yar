rule TTP_XOR_WriteProcessMemory_e7cd {
  strings:
    $key_e7cd = { b0 bf [2] 82 9d [2] 84 a8 [2] aa a8 [2] 95 b4 }

  condition:
    any of them
}