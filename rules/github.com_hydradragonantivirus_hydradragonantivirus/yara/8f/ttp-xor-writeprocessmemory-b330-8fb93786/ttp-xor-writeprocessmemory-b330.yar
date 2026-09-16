rule TTP_XOR_WriteProcessMemory_b330 {
  strings:
    $key_b330 = { e4 42 [2] d6 60 [2] d0 55 [2] fe 55 [2] c1 49 }

  condition:
    any of them
}