rule TTP_XOR_WriteProcessMemory_a73c {
  strings:
    $key_a73c = { f0 4e [2] c2 6c [2] c4 59 [2] ea 59 [2] d5 45 }

  condition:
    any of them
}