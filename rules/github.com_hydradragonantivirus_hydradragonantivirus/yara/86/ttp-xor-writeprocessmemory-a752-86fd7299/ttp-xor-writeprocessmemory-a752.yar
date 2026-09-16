rule TTP_XOR_WriteProcessMemory_a752 {
  strings:
    $key_a752 = { f0 20 [2] c2 02 [2] c4 37 [2] ea 37 [2] d5 2b }

  condition:
    any of them
}