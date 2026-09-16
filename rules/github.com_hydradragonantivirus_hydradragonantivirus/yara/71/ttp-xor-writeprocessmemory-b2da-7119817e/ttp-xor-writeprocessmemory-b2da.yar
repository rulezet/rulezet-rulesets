rule TTP_XOR_WriteProcessMemory_b2da {
  strings:
    $key_b2da = { e5 a8 [2] d7 8a [2] d1 bf [2] ff bf [2] c0 a3 }

  condition:
    any of them
}