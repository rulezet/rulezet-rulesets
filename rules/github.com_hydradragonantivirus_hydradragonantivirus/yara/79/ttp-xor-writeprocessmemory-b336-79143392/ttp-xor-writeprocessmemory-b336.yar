rule TTP_XOR_WriteProcessMemory_b336 {
  strings:
    $key_b336 = { e4 44 [2] d6 66 [2] d0 53 [2] fe 53 [2] c1 4f }

  condition:
    any of them
}