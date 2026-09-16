rule TTP_XOR_WriteProcessMemory_a52c {
  strings:
    $key_a52c = { f2 5e [2] c0 7c [2] c6 49 [2] e8 49 [2] d7 55 }

  condition:
    any of them
}