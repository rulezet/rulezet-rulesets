rule TTP_XOR_WriteProcessMemory_a082 {
  strings:
    $key_a082 = { f7 f0 [2] c5 d2 [2] c3 e7 [2] ed e7 [2] d2 fb }

  condition:
    any of them
}