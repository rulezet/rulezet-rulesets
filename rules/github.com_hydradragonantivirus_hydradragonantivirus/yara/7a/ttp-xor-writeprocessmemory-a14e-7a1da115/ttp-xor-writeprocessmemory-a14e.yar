rule TTP_XOR_WriteProcessMemory_a14e {
  strings:
    $key_a14e = { f6 3c [2] c4 1e [2] c2 2b [2] ec 2b [2] d3 37 }

  condition:
    any of them
}