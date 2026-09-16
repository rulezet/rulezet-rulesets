rule TTP_XOR_WriteProcessMemory_a194 {
  strings:
    $key_a194 = { f6 e6 [2] c4 c4 [2] c2 f1 [2] ec f1 [2] d3 ed }

  condition:
    any of them
}