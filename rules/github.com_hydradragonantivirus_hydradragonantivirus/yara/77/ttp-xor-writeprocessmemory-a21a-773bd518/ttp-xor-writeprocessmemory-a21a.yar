rule TTP_XOR_WriteProcessMemory_a21a {
  strings:
    $key_a21a = { f5 68 [2] c7 4a [2] c1 7f [2] ef 7f [2] d0 63 }

  condition:
    any of them
}