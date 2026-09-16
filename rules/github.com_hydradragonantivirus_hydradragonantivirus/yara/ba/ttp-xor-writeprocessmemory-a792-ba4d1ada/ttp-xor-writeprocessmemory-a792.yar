rule TTP_XOR_WriteProcessMemory_a792 {
  strings:
    $key_a792 = { f0 e0 [2] c2 c2 [2] c4 f7 [2] ea f7 [2] d5 eb }

  condition:
    any of them
}