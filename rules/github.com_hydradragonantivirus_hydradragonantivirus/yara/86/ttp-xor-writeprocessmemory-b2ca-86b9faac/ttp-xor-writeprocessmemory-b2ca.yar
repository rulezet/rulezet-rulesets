rule TTP_XOR_WriteProcessMemory_b2ca {
  strings:
    $key_b2ca = { e5 b8 [2] d7 9a [2] d1 af [2] ff af [2] c0 b3 }

  condition:
    any of them
}