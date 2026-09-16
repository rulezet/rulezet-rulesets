rule TTP_XOR_WriteProcessMemory_b318 {
  strings:
    $key_b318 = { e4 6a [2] d6 48 [2] d0 7d [2] fe 7d [2] c1 61 }

  condition:
    any of them
}