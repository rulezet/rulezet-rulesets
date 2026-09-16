rule TTP_XOR_WriteProcessMemory_a1f6 {
  strings:
    $key_a1f6 = { f6 84 [2] c4 a6 [2] c2 93 [2] ec 93 [2] d3 8f }

  condition:
    any of them
}