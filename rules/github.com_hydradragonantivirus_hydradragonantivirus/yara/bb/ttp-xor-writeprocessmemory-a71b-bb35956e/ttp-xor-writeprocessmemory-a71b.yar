rule TTP_XOR_WriteProcessMemory_a71b {
  strings:
    $key_a71b = { f0 69 [2] c2 4b [2] c4 7e [2] ea 7e [2] d5 62 }

  condition:
    any of them
}