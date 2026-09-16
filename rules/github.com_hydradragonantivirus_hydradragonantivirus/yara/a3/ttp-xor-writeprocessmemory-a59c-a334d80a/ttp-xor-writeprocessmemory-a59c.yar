rule TTP_XOR_WriteProcessMemory_a59c {
  strings:
    $key_a59c = { f2 ee [2] c0 cc [2] c6 f9 [2] e8 f9 [2] d7 e5 }

  condition:
    any of them
}