rule TTP_XOR_WriteProcessMemory_a736 {
  strings:
    $key_a736 = { f0 44 [2] c2 66 [2] c4 53 [2] ea 53 [2] d5 4f }

  condition:
    any of them
}