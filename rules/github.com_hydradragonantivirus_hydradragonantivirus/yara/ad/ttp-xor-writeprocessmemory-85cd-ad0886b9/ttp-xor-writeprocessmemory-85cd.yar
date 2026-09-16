rule TTP_XOR_WriteProcessMemory_85cd {
  strings:
    $key_85cd = { d2 bf [2] e0 9d [2] e6 a8 [2] c8 a8 [2] f7 b4 }

  condition:
    any of them
}