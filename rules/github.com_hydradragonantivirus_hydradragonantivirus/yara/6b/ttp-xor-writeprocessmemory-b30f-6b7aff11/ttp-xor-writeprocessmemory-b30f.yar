rule TTP_XOR_WriteProcessMemory_b30f {
  strings:
    $key_b30f = { e4 7d [2] d6 5f [2] d0 6a [2] fe 6a [2] c1 76 }

  condition:
    any of them
}