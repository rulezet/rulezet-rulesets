rule TTP_XOR_WriteProcessMemory_a3ca {
  strings:
    $key_a3ca = { f4 b8 [2] c6 9a [2] c0 af [2] ee af [2] d1 b3 }

  condition:
    any of them
}