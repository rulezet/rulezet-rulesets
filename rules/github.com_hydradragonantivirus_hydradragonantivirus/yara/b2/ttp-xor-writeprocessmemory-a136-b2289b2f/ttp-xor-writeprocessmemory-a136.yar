rule TTP_XOR_WriteProcessMemory_a136 {
  strings:
    $key_a136 = { f6 44 [2] c4 66 [2] c2 53 [2] ec 53 [2] d3 4f }

  condition:
    any of them
}