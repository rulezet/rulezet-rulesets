rule TTP_XOR_WriteProcessMemory_a161 {
  strings:
    $key_a161 = { f6 13 [2] c4 31 [2] c2 04 [2] ec 04 [2] d3 18 }

  condition:
    any of them
}