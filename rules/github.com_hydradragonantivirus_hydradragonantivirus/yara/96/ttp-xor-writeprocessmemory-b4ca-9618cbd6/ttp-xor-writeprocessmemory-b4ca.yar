rule TTP_XOR_WriteProcessMemory_b4ca {
  strings:
    $key_b4ca = { e3 b8 [2] d1 9a [2] d7 af [2] f9 af [2] c6 b3 }

  condition:
    any of them
}