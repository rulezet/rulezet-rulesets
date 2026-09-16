rule TTP_XOR_WriteProcessMemory_a0ef {
  strings:
    $key_a0ef = { f7 9d [2] c5 bf [2] c3 8a [2] ed 8a [2] d2 96 }

  condition:
    any of them
}