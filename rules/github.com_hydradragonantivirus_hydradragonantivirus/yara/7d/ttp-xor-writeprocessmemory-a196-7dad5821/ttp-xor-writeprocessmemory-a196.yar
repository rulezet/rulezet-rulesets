rule TTP_XOR_WriteProcessMemory_a196 {
  strings:
    $key_a196 = { f6 e4 [2] c4 c6 [2] c2 f3 [2] ec f3 [2] d3 ef }

  condition:
    any of them
}