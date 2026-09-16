rule TTP_XOR_WriteProcessMemory_b3f9 {
  strings:
    $key_b3f9 = { e4 8b [2] d6 a9 [2] d0 9c [2] fe 9c [2] c1 80 }

  condition:
    any of them
}