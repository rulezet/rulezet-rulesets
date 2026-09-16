rule TTP_XOR_WriteProcessMemory_85ef {
  strings:
    $key_85ef = { d2 9d [2] e0 bf [2] e6 8a [2] c8 8a [2] f7 96 }

  condition:
    any of them
}