rule TTP_XOR_WriteProcessMemory_97ef {
  strings:
    $key_97ef = { c0 9d [2] f2 bf [2] f4 8a [2] da 8a [2] e5 96 }

  condition:
    any of them
}