rule TTP_XOR_WriteProcessMemory_a1d1 {
  strings:
    $key_a1d1 = { f6 a3 [2] c4 81 [2] c2 b4 [2] ec b4 [2] d3 a8 }

  condition:
    any of them
}