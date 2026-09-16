rule TTP_XOR_WriteProcessMemory_a74c {
  strings:
    $key_a74c = { f0 3e [2] c2 1c [2] c4 29 [2] ea 29 [2] d5 35 }

  condition:
    any of them
}