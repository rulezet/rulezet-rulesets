rule TTP_XOR_WriteProcessMemory_84ef {
  strings:
    $key_84ef = { d3 9d [2] e1 bf [2] e7 8a [2] c9 8a [2] f6 96 }

  condition:
    any of them
}