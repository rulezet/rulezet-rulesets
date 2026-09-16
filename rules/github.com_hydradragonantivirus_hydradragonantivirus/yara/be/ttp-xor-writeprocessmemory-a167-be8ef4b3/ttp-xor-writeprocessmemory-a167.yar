rule TTP_XOR_WriteProcessMemory_a167 {
  strings:
    $key_a167 = { f6 15 [2] c4 37 [2] c2 02 [2] ec 02 [2] d3 1e }

  condition:
    any of them
}