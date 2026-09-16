rule TTP_XOR_WriteProcessMemory_b51b {
  strings:
    $key_b51b = { e2 69 [2] d0 4b [2] d6 7e [2] f8 7e [2] c7 62 }

  condition:
    any of them
}