rule TTP_XOR_WriteProcessMemory_a172 {
  strings:
    $key_a172 = { f6 00 [2] c4 22 [2] c2 17 [2] ec 17 [2] d3 0b }

  condition:
    any of them
}