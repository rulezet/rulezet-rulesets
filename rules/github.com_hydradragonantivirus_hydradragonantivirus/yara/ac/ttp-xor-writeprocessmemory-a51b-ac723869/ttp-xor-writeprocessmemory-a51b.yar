rule TTP_XOR_WriteProcessMemory_a51b {
  strings:
    $key_a51b = { f2 69 [2] c0 4b [2] c6 7e [2] e8 7e [2] d7 62 }

  condition:
    any of them
}