rule TTP_XOR_WriteProcessMemory_a74b {
  strings:
    $key_a74b = { f0 39 [2] c2 1b [2] c4 2e [2] ea 2e [2] d5 32 }

  condition:
    any of them
}