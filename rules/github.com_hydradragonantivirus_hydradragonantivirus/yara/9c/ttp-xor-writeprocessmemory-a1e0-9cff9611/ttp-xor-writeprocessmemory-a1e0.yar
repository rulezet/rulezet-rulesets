rule TTP_XOR_WriteProcessMemory_a1e0 {
  strings:
    $key_a1e0 = { f6 92 [2] c4 b0 [2] c2 85 [2] ec 85 [2] d3 99 }

  condition:
    any of them
}