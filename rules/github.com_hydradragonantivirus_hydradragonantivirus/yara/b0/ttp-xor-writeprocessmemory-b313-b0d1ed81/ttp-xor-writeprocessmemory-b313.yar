rule TTP_XOR_WriteProcessMemory_b313 {
  strings:
    $key_b313 = { e4 61 [2] d6 43 [2] d0 76 [2] fe 76 [2] c1 6a }

  condition:
    any of them
}