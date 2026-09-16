rule TTP_XOR_WriteProcessMemory_a79c {
  strings:
    $key_a79c = { f0 ee [2] c2 cc [2] c4 f9 [2] ea f9 [2] d5 e5 }

  condition:
    any of them
}