rule TTP_XOR_WriteProcessMemory_80cd {
  strings:
    $key_80cd = { d7 bf [2] e5 9d [2] e3 a8 [2] cd a8 [2] f2 b4 }

  condition:
    any of them
}