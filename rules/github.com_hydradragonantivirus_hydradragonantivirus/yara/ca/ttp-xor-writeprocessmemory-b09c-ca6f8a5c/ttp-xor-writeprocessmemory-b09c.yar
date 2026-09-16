rule TTP_XOR_WriteProcessMemory_b09c {
  strings:
    $key_b09c = { e7 ee [2] d5 cc [2] d3 f9 [2] fd f9 [2] c2 e5 }

  condition:
    any of them
}