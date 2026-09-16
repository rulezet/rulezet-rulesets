rule TTP_XOR_WriteProcessMemory_a708 {
  strings:
    $key_a708 = { f0 7a [2] c2 58 [2] c4 6d [2] ea 6d [2] d5 71 }

  condition:
    any of them
}