rule TTP_XOR_WriteProcessMemory_a774 {
  strings:
    $key_a774 = { f0 06 [2] c2 24 [2] c4 11 [2] ea 11 [2] d5 0d }

  condition:
    any of them
}