rule TTP_XOR_WriteProcessMemory_a49c {
  strings:
    $key_a49c = { f3 ee [2] c1 cc [2] c7 f9 [2] e9 f9 [2] d6 e5 }

  condition:
    any of them
}