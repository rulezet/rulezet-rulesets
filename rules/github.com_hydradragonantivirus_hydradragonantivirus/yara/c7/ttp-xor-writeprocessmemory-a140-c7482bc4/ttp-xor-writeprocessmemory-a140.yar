rule TTP_XOR_WriteProcessMemory_a140 {
  strings:
    $key_a140 = { f6 32 [2] c4 10 [2] c2 25 [2] ec 25 [2] d3 39 }

  condition:
    any of them
}