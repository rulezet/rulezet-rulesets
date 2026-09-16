rule TTP_XOR_WriteProcessMemory_a5f9 {
  strings:
    $key_a5f9 = { f2 8b [2] c0 a9 [2] c6 9c [2] e8 9c [2] d7 80 }

  condition:
    any of them
}