rule TTP_XOR_WriteProcessMemory_b55b {
  strings:
    $key_b55b = { e2 29 [2] d0 0b [2] d6 3e [2] f8 3e [2] c7 22 }

  condition:
    any of them
}