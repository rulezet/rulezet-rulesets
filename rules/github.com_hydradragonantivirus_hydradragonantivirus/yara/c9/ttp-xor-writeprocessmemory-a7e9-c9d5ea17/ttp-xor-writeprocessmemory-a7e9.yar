rule TTP_XOR_WriteProcessMemory_a7e9 {
  strings:
    $key_a7e9 = { f0 9b [2] c2 b9 [2] c4 8c [2] ea 8c [2] d5 90 }

  condition:
    any of them
}