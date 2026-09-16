rule TTP_XOR_WriteProcessMemory_b310 {
  strings:
    $key_b310 = { e4 62 [2] d6 40 [2] d0 75 [2] fe 75 [2] c1 69 }

  condition:
    any of them
}