rule TTP_XOR_WriteProcessMemory_a71f {
  strings:
    $key_a71f = { f0 6d [2] c2 4f [2] c4 7a [2] ea 7a [2] d5 66 }

  condition:
    any of them
}