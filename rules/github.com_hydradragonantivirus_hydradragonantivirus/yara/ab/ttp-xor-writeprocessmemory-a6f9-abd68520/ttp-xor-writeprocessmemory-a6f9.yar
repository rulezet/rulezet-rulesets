rule TTP_XOR_WriteProcessMemory_a6f9 {
  strings:
    $key_a6f9 = { f1 8b [2] c3 a9 [2] c5 9c [2] eb 9c [2] d4 80 }

  condition:
    any of them
}