rule TTP_XOR_WriteProcessMemory_a191 {
  strings:
    $key_a191 = { f6 e3 [2] c4 c1 [2] c2 f4 [2] ec f4 [2] d3 e8 }

  condition:
    any of them
}