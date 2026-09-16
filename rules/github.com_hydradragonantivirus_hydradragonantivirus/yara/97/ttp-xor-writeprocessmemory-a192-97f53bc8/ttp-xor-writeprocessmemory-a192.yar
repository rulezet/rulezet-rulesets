rule TTP_XOR_WriteProcessMemory_a192 {
  strings:
    $key_a192 = { f6 e0 [2] c4 c2 [2] c2 f7 [2] ec f7 [2] d3 eb }

  condition:
    any of them
}