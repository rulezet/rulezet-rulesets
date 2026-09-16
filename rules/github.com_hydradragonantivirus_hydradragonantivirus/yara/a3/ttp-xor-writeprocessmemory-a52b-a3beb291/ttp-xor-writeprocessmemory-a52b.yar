rule TTP_XOR_WriteProcessMemory_a52b {
  strings:
    $key_a52b = { f2 59 [2] c0 7b [2] c6 4e [2] e8 4e [2] d7 52 }

  condition:
    any of them
}