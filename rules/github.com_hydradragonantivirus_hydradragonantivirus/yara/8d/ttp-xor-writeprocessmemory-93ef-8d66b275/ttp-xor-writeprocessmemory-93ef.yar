rule TTP_XOR_WriteProcessMemory_93ef {
  strings:
    $key_93ef = { c4 9d [2] f6 bf [2] f0 8a [2] de 8a [2] e1 96 }

  condition:
    any of them
}