rule TTP_XOR_WriteProcessMemory_a10b {
  strings:
    $key_a10b = { f6 79 [2] c4 5b [2] c2 6e [2] ec 6e [2] d3 72 }

  condition:
    any of them
}