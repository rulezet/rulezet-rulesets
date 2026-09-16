rule TTP_XOR_WriteProcessMemory_a75a {
  strings:
    $key_a75a = { f0 28 [2] c2 0a [2] c4 3f [2] ea 3f [2] d5 23 }

  condition:
    any of them
}