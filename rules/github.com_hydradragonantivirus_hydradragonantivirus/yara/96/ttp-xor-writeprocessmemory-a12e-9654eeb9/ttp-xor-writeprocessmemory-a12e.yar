rule TTP_XOR_WriteProcessMemory_a12e {
  strings:
    $key_a12e = { f6 5c [2] c4 7e [2] c2 4b [2] ec 4b [2] d3 57 }

  condition:
    any of them
}