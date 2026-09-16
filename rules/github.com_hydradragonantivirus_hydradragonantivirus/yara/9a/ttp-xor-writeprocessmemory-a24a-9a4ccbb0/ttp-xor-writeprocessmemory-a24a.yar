rule TTP_XOR_WriteProcessMemory_a24a {
  strings:
    $key_a24a = { f5 38 [2] c7 1a [2] c1 2f [2] ef 2f [2] d0 33 }

  condition:
    any of them
}