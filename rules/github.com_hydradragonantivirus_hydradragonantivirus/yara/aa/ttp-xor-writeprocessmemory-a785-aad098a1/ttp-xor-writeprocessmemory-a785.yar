rule TTP_XOR_WriteProcessMemory_a785 {
  strings:
    $key_a785 = { f0 f7 [2] c2 d5 [2] c4 e0 [2] ea e0 [2] d5 fc }

  condition:
    any of them
}