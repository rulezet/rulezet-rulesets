rule TTP_XOR_WriteProcessMemory_b47c {
  strings:
    $key_b47c = { e3 0e [2] d1 2c [2] d7 19 [2] f9 19 [2] c6 05 }

  condition:
    any of them
}