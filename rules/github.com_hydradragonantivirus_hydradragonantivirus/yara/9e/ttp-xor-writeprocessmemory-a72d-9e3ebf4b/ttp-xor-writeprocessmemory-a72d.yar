rule TTP_XOR_WriteProcessMemory_a72d {
  strings:
    $key_a72d = { f0 5f [2] c2 7d [2] c4 48 [2] ea 48 [2] d5 54 }

  condition:
    any of them
}