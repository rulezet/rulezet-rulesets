rule TTP_XOR_WriteProcessMemory_a748 {
  strings:
    $key_a748 = { f0 3a [2] c2 18 [2] c4 2d [2] ea 2d [2] d5 31 }

  condition:
    any of them
}