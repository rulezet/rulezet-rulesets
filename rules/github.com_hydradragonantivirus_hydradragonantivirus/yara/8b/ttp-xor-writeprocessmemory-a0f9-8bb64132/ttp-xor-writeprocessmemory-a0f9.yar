rule TTP_XOR_WriteProcessMemory_a0f9 {
  strings:
    $key_a0f9 = { f7 8b [2] c5 a9 [2] c3 9c [2] ed 9c [2] d2 80 }

  condition:
    any of them
}