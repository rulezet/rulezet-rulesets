rule TTP_XOR_WriteProcessMemory_b44c {
  strings:
    $key_b44c = { e3 3e [2] d1 1c [2] d7 29 [2] f9 29 [2] c6 35 }

  condition:
    any of them
}