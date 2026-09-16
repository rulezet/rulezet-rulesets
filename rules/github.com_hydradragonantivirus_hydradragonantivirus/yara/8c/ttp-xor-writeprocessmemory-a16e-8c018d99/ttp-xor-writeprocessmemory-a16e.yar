rule TTP_XOR_WriteProcessMemory_a16e {
  strings:
    $key_a16e = { f6 1c [2] c4 3e [2] c2 0b [2] ec 0b [2] d3 17 }

  condition:
    any of them
}