rule TTP_XOR_WriteProcessMemory_a173 {
  strings:
    $key_a173 = { f6 01 [2] c4 23 [2] c2 16 [2] ec 16 [2] d3 0a }

  condition:
    any of them
}