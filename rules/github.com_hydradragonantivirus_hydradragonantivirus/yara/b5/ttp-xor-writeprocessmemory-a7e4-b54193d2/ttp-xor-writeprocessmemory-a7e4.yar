rule TTP_XOR_WriteProcessMemory_a7e4 {
  strings:
    $key_a7e4 = { f0 96 [2] c2 b4 [2] c4 81 [2] ea 81 [2] d5 9d }

  condition:
    any of them
}