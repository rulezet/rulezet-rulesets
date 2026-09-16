rule TTP_XOR_WriteProcessMemory_b54c {
  strings:
    $key_b54c = { e2 3e [2] d0 1c [2] d6 29 [2] f8 29 [2] c7 35 }

  condition:
    any of them
}