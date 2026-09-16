rule TTP_XOR_WriteProcessMemory_a738 {
  strings:
    $key_a738 = { f0 4a [2] c2 68 [2] c4 5d [2] ea 5d [2] d5 41 }

  condition:
    any of them
}