rule TTP_XOR_WriteProcessMemory_a5da {
  strings:
    $key_a5da = { f2 a8 [2] c0 8a [2] c6 bf [2] e8 bf [2] d7 a3 }

  condition:
    any of them
}