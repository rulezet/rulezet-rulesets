rule TTP_XOR_WriteProcessMemory_a14b {
  strings:
    $key_a14b = { f6 39 [2] c4 1b [2] c2 2e [2] ec 2e [2] d3 32 }

  condition:
    any of them
}