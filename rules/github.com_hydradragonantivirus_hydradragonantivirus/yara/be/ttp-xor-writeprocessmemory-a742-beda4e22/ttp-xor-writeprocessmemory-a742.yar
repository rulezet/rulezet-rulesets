rule TTP_XOR_WriteProcessMemory_a742 {
  strings:
    $key_a742 = { f0 30 [2] c2 12 [2] c4 27 [2] ea 27 [2] d5 3b }

  condition:
    any of them
}