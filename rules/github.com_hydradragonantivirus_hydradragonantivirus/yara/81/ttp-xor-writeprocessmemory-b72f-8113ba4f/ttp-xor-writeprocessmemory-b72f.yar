rule TTP_XOR_WriteProcessMemory_b72f {
  strings:
    $key_b72f = { e0 5d [2] d2 7f [2] d4 4a [2] fa 4a [2] c5 56 }

  condition:
    any of them
}