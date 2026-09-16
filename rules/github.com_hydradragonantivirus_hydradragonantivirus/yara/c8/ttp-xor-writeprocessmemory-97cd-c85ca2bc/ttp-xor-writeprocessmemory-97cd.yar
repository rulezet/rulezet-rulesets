rule TTP_XOR_WriteProcessMemory_97cd {
  strings:
    $key_97cd = { c0 bf [2] f2 9d [2] f4 a8 [2] da a8 [2] e5 b4 }

  condition:
    any of them
}