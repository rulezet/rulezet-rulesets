rule TTP_XOR_WriteProcessMemory_a22d {
  strings:
    $key_a22d = { f5 5f [2] c7 7d [2] c1 48 [2] ef 48 [2] d0 54 }

  condition:
    any of them
}