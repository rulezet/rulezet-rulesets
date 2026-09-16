rule TTP_XOR_WriteProcessMemory_873b {
  strings:
    $key_873b = { d0 49 [2] e2 6b [2] e4 5e [2] ca 5e [2] f5 42 }

  condition:
    any of them
}