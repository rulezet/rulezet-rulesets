rule TTP_XOR_WriteProcessMemory_a156 {
  strings:
    $key_a156 = { f6 24 [2] c4 06 [2] c2 33 [2] ec 33 [2] d3 2f }

  condition:
    any of them
}