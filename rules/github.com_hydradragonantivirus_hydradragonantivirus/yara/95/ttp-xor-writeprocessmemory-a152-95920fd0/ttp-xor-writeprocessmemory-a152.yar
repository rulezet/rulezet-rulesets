rule TTP_XOR_WriteProcessMemory_a152 {
  strings:
    $key_a152 = { f6 20 [2] c4 02 [2] c2 37 [2] ec 37 [2] d3 2b }

  condition:
    any of them
}