rule TTP_XOR_WriteProcessMemory_b11f {
  strings:
    $key_b11f = { e6 6d [2] d4 4f [2] d2 7a [2] fc 7a [2] c3 66 }

  condition:
    any of them
}