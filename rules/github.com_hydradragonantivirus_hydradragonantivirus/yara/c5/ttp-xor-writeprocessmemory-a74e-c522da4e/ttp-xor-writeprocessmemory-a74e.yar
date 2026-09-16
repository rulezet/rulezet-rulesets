rule TTP_XOR_WriteProcessMemory_a74e {
  strings:
    $key_a74e = { f0 3c [2] c2 1e [2] c4 2b [2] ea 2b [2] d5 37 }

  condition:
    any of them
}