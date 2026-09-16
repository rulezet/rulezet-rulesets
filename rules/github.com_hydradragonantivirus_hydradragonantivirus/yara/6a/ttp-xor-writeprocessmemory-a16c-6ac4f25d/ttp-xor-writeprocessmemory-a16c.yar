rule TTP_XOR_WriteProcessMemory_a16c {
  strings:
    $key_a16c = { f6 1e [2] c4 3c [2] c2 09 [2] ec 09 [2] d3 15 }

  condition:
    any of them
}