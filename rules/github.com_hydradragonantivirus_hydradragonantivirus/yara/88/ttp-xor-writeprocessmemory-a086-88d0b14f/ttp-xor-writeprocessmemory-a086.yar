rule TTP_XOR_WriteProcessMemory_a086 {
  strings:
    $key_a086 = { f7 f4 [2] c5 d6 [2] c3 e3 [2] ed e3 [2] d2 ff }

  condition:
    any of them
}