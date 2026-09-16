rule TTP_XOR_WriteProcessMemory_a11e {
  strings:
    $key_a11e = { f6 6c [2] c4 4e [2] c2 7b [2] ec 7b [2] d3 67 }

  condition:
    any of them
}