rule TTP_XOR_WriteProcessMemory_a3da {
  strings:
    $key_a3da = { f4 a8 [2] c6 8a [2] c0 bf [2] ee bf [2] d1 a3 }

  condition:
    any of them
}