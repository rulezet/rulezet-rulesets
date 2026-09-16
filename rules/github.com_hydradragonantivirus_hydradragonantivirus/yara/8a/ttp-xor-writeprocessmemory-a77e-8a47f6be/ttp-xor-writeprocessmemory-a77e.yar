rule TTP_XOR_WriteProcessMemory_a77e {
  strings:
    $key_a77e = { f0 0c [2] c2 2e [2] c4 1b [2] ea 1b [2] d5 07 }

  condition:
    any of them
}