rule TTP_XOR_WriteProcessMemory_a71d {
  strings:
    $key_a71d = { f0 6f [2] c2 4d [2] c4 78 [2] ea 78 [2] d5 64 }

  condition:
    any of them
}