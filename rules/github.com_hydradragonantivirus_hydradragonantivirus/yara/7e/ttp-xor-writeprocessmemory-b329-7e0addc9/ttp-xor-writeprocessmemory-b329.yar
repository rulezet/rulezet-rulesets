rule TTP_XOR_WriteProcessMemory_b329 {
  strings:
    $key_b329 = { e4 5b [2] d6 79 [2] d0 4c [2] fe 4c [2] c1 50 }

  condition:
    any of them
}