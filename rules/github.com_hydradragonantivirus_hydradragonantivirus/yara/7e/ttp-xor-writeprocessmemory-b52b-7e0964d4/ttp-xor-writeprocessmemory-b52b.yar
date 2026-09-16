rule TTP_XOR_WriteProcessMemory_b52b {
  strings:
    $key_b52b = { e2 59 [2] d0 7b [2] d6 4e [2] f8 4e [2] c7 52 }

  condition:
    any of them
}