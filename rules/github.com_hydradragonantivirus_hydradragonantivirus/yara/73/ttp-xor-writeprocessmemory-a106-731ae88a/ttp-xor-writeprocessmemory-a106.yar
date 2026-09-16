rule TTP_XOR_WriteProcessMemory_a106 {
  strings:
    $key_a106 = { f6 74 [2] c4 56 [2] c2 63 [2] ec 63 [2] d3 7f }

  condition:
    any of them
}