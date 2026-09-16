rule TTP_XOR_WriteProcessMemory_b353 {
  strings:
    $key_b353 = { e4 21 [2] d6 03 [2] d0 36 [2] fe 36 [2] c1 2a }

  condition:
    any of them
}