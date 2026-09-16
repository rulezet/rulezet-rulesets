rule TTP_XOR_WriteProcessMemory_a0e9 {
  strings:
    $key_a0e9 = { f7 9b [2] c5 b9 [2] c3 8c [2] ed 8c [2] d2 90 }

  condition:
    any of them
}