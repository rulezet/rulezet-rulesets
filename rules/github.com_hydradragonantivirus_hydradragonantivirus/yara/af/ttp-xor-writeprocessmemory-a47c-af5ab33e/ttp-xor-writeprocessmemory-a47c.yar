rule TTP_XOR_WriteProcessMemory_a47c {
  strings:
    $key_a47c = { f3 0e [2] c1 2c [2] c7 19 [2] e9 19 [2] d6 05 }

  condition:
    any of them
}