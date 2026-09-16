rule TTP_XOR_WriteProcessMemory_a778 {
  strings:
    $key_a778 = { f0 0a [2] c2 28 [2] c4 1d [2] ea 1d [2] d5 01 }

  condition:
    any of them
}