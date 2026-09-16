rule TTP_XOR_WriteProcessMemory_a185 {
  strings:
    $key_a185 = { f6 f7 [2] c4 d5 [2] c2 e0 [2] ec e0 [2] d3 fc }

  condition:
    any of them
}