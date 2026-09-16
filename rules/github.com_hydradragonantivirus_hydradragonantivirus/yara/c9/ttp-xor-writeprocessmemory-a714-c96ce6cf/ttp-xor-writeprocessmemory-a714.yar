rule TTP_XOR_WriteProcessMemory_a714 {
  strings:
    $key_a714 = { f0 66 [2] c2 44 [2] c4 71 [2] ea 71 [2] d5 6d }

  condition:
    any of them
}