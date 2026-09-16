rule TTP_XOR_WriteProcessMemory_843b {
  strings:
    $key_843b = { d3 49 [2] e1 6b [2] e7 5e [2] c9 5e [2] f6 42 }

  condition:
    any of them
}