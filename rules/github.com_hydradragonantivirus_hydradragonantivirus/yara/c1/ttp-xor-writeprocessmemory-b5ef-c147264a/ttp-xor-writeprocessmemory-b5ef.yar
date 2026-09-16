rule TTP_XOR_WriteProcessMemory_b5ef {
  strings:
    $key_b5ef = { e2 9d [2] d0 bf [2] d6 8a [2] f8 8a [2] c7 96 }

  condition:
    any of them
}