rule TTP_XOR_WriteProcessMemory_a7da {
  strings:
    $key_a7da = { f0 a8 [2] c2 8a [2] c4 bf [2] ea bf [2] d5 a3 }

  condition:
    any of them
}