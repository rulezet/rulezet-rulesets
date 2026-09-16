rule TTP_XOR_WriteProcessMemory_91ef {
  strings:
    $key_91ef = { c6 9d [2] f4 bf [2] f2 8a [2] dc 8a [2] e3 96 }

  condition:
    any of them
}