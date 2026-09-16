rule TTP_XOR_WriteProcessMemory_b57c {
  strings:
    $key_b57c = { e2 0e [2] d0 2c [2] d6 19 [2] f8 19 [2] c7 05 }

  condition:
    any of them
}