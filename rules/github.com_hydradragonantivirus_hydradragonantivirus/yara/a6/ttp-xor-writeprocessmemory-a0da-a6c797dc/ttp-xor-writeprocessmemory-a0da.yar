rule TTP_XOR_WriteProcessMemory_a0da {
  strings:
    $key_a0da = { f7 a8 [2] c5 8a [2] c3 bf [2] ed bf [2] d2 a3 }

  condition:
    any of them
}