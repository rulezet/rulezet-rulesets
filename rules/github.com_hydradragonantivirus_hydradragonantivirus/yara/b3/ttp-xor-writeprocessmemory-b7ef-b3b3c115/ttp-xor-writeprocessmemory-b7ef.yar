rule TTP_XOR_WriteProcessMemory_b7ef {
  strings:
    $key_b7ef = { e0 9d [2] d2 bf [2] d4 8a [2] fa 8a [2] c5 96 }

  condition:
    any of them
}