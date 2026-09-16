rule TTP_XOR_WriteProcessMemory_a76b {
  strings:
    $key_a76b = { f0 19 [2] c2 3b [2] c4 0e [2] ea 0e [2] d5 12 }

  condition:
    any of them
}