rule TTP_XOR_WriteProcessMemory_a10e {
  strings:
    $key_a10e = { f6 7c [2] c4 5e [2] c2 6b [2] ec 6b [2] d3 77 }

  condition:
    any of them
}