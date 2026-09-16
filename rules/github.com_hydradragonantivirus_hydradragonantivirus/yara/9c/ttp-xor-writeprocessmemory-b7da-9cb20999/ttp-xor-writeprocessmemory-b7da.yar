rule TTP_XOR_WriteProcessMemory_b7da {
  strings:
    $key_b7da = { e0 a8 [2] d2 8a [2] d4 bf [2] fa bf [2] c5 a3 }

  condition:
    any of them
}