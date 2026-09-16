rule TTP_XOR_WriteProcessMemory_b375 {
  strings:
    $key_b375 = { e4 07 [2] d6 25 [2] d0 10 [2] fe 10 [2] c1 0c }

  condition:
    any of them
}