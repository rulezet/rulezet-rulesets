rule TTP_XOR_WriteProcessMemory_a17e {
  strings:
    $key_a17e = { f6 0c [2] c4 2e [2] c2 1b [2] ec 1b [2] d3 07 }

  condition:
    any of them
}