rule TTP_XOR_WriteProcessMemory_b7ca {
  strings:
    $key_b7ca = { e0 b8 [2] d2 9a [2] d4 af [2] fa af [2] c5 b3 }

  condition:
    any of them
}