rule TTP_XOR_WriteProcessMemory_a53f {
  strings:
    $key_a53f = { f2 4d [2] c0 6f [2] c6 5a [2] e8 5a [2] d7 46 }

  condition:
    any of them
}