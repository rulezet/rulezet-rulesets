rule TTP_XOR_WriteProcessMemory_81ef {
  strings:
    $key_81ef = { d6 9d [2] e4 bf [2] e2 8a [2] cc 8a [2] f3 96 }

  condition:
    any of them
}