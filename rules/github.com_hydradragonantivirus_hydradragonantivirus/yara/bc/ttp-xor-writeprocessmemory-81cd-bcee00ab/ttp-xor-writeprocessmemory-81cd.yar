rule TTP_XOR_WriteProcessMemory_81cd {
  strings:
    $key_81cd = { d6 bf [2] e4 9d [2] e2 a8 [2] cc a8 [2] f3 b4 }

  condition:
    any of them
}