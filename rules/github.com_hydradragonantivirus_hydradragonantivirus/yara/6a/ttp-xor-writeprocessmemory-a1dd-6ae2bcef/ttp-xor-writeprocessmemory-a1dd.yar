rule TTP_XOR_WriteProcessMemory_a1dd {
  strings:
    $key_a1dd = { f6 af [2] c4 8d [2] c2 b8 [2] ec b8 [2] d3 a4 }

  condition:
    any of them
}