rule TTP_XOR_WriteProcessMemory_a7ca {
  strings:
    $key_a7ca = { f0 b8 [2] c2 9a [2] c4 af [2] ea af [2] d5 b3 }

  condition:
    any of them
}