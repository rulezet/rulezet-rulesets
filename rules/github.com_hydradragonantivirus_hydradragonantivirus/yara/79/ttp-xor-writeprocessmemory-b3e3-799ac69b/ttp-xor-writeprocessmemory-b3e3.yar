rule TTP_XOR_WriteProcessMemory_b3e3 {
  strings:
    $key_b3e3 = { e4 91 [2] d6 b3 [2] d0 86 [2] fe 86 [2] c1 9a }

  condition:
    any of them
}