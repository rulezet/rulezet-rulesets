rule TTP_XOR_WriteProcessMemory_a197 {
  strings:
    $key_a197 = { f6 e5 [2] c4 c7 [2] c2 f2 [2] ec f2 [2] d3 ee }

  condition:
    any of them
}