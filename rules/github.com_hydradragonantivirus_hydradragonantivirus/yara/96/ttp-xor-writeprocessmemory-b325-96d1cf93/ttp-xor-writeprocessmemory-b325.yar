rule TTP_XOR_WriteProcessMemory_b325 {
  strings:
    $key_b325 = { e4 57 [2] d6 75 [2] d0 40 [2] fe 40 [2] c1 5c }

  condition:
    any of them
}