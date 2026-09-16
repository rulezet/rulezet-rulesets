rule TTP_XOR_WriteProcessMemory_b349 {
  strings:
    $key_b349 = { e4 3b [2] d6 19 [2] d0 2c [2] fe 2c [2] c1 30 }

  condition:
    any of them
}