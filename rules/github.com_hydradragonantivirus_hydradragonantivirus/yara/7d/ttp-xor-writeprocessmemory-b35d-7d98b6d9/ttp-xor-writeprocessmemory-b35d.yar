rule TTP_XOR_WriteProcessMemory_b35d {
  strings:
    $key_b35d = { e4 2f [2] d6 0d [2] d0 38 [2] fe 38 [2] c1 24 }

  condition:
    any of them
}