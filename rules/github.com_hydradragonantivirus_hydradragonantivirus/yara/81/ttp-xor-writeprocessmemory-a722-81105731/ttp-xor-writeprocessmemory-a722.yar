rule TTP_XOR_WriteProcessMemory_a722 {
  strings:
    $key_a722 = { f0 50 [2] c2 72 [2] c4 47 [2] ea 47 [2] d5 5b }

  condition:
    any of them
}