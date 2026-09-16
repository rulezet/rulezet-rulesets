rule TTP_XOR_WriteProcessMemory_b32d {
  strings:
    $key_b32d = { e4 5f [2] d6 7d [2] d0 48 [2] fe 48 [2] c1 54 }

  condition:
    any of them
}