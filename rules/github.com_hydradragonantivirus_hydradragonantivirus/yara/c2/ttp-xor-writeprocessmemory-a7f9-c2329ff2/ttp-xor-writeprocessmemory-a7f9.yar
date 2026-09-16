rule TTP_XOR_WriteProcessMemory_a7f9 {
  strings:
    $key_a7f9 = { f0 8b [2] c2 a9 [2] c4 9c [2] ea 9c [2] d5 80 }

  condition:
    any of them
}