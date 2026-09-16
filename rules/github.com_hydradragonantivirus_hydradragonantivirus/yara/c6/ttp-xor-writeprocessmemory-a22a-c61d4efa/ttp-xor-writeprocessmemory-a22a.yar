rule TTP_XOR_WriteProcessMemory_a22a {
  strings:
    $key_a22a = { f5 58 [2] c7 7a [2] c1 4f [2] ef 4f [2] d0 53 }

  condition:
    any of them
}