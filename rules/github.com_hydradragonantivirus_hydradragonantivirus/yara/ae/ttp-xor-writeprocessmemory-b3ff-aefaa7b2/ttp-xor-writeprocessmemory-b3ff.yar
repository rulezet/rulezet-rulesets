rule TTP_XOR_WriteProcessMemory_b3ff {
  strings:
    $key_b3ff = { e4 8d [2] d6 af [2] d0 9a [2] fe 9a [2] c1 86 }

  condition:
    any of them
}