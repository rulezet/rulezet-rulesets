rule TTP_XOR_WriteProcessMemory_851b {
  strings:
    $key_851b = { d2 69 [2] e0 4b [2] e6 7e [2] c8 7e [2] f7 62 }

  condition:
    any of them
}