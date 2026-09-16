rule TTP_XOR_WriteProcessMemory_b5da {
  strings:
    $key_b5da = { e2 a8 [2] d0 8a [2] d6 bf [2] f8 bf [2] c7 a3 }

  condition:
    any of them
}