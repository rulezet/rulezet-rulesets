rule TTP_XOR_WriteProcessMemory_a19c {
  strings:
    $key_a19c = { f6 ee [2] c4 cc [2] c2 f9 [2] ec f9 [2] d3 e5 }

  condition:
    any of them
}