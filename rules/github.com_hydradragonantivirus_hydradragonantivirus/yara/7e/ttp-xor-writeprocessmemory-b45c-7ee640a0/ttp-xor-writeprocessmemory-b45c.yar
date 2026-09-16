rule TTP_XOR_WriteProcessMemory_b45c {
  strings:
    $key_b45c = { e3 2e [2] d1 0c [2] d7 39 [2] f9 39 [2] c6 25 }

  condition:
    any of them
}