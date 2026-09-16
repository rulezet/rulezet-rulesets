rule TTP_XOR_WriteProcessMemory_b15f {
  strings:
    $key_b15f = { e6 2d [2] d4 0f [2] d2 3a [2] fc 3a [2] c3 26 }

  condition:
    any of them
}