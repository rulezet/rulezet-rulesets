rule TTP_XOR_WriteProcessMemory_a71e {
  strings:
    $key_a71e = { f0 6c [2] c2 4e [2] c4 7b [2] ea 7b [2] d5 67 }

  condition:
    any of them
}