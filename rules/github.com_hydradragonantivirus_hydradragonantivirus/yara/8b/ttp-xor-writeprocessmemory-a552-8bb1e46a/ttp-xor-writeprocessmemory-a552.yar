rule TTP_XOR_WriteProcessMemory_a552 {
  strings:
    $key_a552 = { f2 20 [2] c0 02 [2] c6 37 [2] e8 37 [2] d7 2b }

  condition:
    any of them
}