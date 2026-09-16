rule TTP_XOR_WriteProcessMemory_a519 {
  strings:
    $key_a519 = { f2 6b [2] c0 49 [2] c6 7c [2] e8 7c [2] d7 60 }

  condition:
    any of them
}