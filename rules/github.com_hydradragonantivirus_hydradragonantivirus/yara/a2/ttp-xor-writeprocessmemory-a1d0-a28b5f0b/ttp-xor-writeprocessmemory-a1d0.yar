rule TTP_XOR_WriteProcessMemory_a1d0 {
  strings:
    $key_a1d0 = { f6 a2 [2] c4 80 [2] c2 b5 [2] ec b5 [2] d3 a9 }

  condition:
    any of them
}