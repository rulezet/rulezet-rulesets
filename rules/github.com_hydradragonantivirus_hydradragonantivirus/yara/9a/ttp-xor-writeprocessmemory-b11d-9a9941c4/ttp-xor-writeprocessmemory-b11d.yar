rule TTP_XOR_WriteProcessMemory_b11d {
  strings:
    $key_b11d = { e6 6f [2] d4 4d [2] d2 78 [2] fc 78 [2] c3 64 }

  condition:
    any of them
}