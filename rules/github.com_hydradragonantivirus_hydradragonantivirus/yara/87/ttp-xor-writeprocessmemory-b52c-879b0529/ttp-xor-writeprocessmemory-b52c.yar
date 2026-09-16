rule TTP_XOR_WriteProcessMemory_b52c {
  strings:
    $key_b52c = { e2 5e [2] d0 7c [2] d6 49 [2] f8 49 [2] c7 55 }

  condition:
    any of them
}