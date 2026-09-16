rule TTP_XOR_WriteProcessMemory_a77d {
  strings:
    $key_a77d = { f0 0f [2] c2 2d [2] c4 18 [2] ea 18 [2] d5 04 }

  condition:
    any of them
}