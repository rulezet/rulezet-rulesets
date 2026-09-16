rule TTP_XOR_WriteProcessMemory_a1e7 {
  strings:
    $key_a1e7 = { f6 95 [2] c4 b7 [2] c2 82 [2] ec 82 [2] d3 9e }

  condition:
    any of them
}