rule TTP_XOR_WriteProcessMemory_a4ef {
  strings:
    $key_a4ef = { f3 9d [2] c1 bf [2] c7 8a [2] e9 8a [2] d6 96 }

  condition:
    any of them
}