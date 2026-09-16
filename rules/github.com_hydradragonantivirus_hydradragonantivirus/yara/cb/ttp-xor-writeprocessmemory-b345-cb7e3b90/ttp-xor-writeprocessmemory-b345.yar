rule TTP_XOR_WriteProcessMemory_b345 {
  strings:
    $key_b345 = { e4 37 [2] d6 15 [2] d0 20 [2] fe 20 [2] c1 3c }

  condition:
    any of them
}