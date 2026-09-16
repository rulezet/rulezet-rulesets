rule TTP_XOR_WriteProcessMemory_b3a8 {
  strings:
    $key_b3a8 = { e4 da [2] d6 f8 [2] d0 cd [2] fe cd [2] c1 d1 }

  condition:
    any of them
}