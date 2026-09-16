rule TTP_XOR_WriteProcessMemory_a749 {
  strings:
    $key_a749 = { f0 3b [2] c2 19 [2] c4 2c [2] ea 2c [2] d5 30 }

  condition:
    any of them
}