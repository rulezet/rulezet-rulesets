rule TTP_XOR_WriteProcessMemory_96ef {
  strings:
    $key_96ef = { c1 9d [2] f3 bf [2] f5 8a [2] db 8a [2] e4 96 }

  condition:
    any of them
}