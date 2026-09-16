rule TTP_XOR_WriteProcessMemory_b3ef {
  strings:
    $key_b3ef = { e4 9d [2] d6 bf [2] d0 8a [2] fe 8a [2] c1 96 }

  condition:
    any of them
}