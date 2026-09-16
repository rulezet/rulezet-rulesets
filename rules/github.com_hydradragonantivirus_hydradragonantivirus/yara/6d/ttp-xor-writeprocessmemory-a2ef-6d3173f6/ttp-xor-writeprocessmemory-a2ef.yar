rule TTP_XOR_WriteProcessMemory_a2ef {
  strings:
    $key_a2ef = { f5 9d [2] c7 bf [2] c1 8a [2] ef 8a [2] d0 96 }

  condition:
    any of them
}