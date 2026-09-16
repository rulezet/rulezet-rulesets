rule TTP_XOR_WriteProcessMemory_a21d {
  strings:
    $key_a21d = { f5 6f [2] c7 4d [2] c1 78 [2] ef 78 [2] d0 64 }

  condition:
    any of them
}