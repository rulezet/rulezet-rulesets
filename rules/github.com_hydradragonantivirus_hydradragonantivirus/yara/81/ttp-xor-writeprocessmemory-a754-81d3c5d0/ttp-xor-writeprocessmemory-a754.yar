rule TTP_XOR_WriteProcessMemory_a754 {
  strings:
    $key_a754 = { f0 26 [2] c2 04 [2] c4 31 [2] ea 31 [2] d5 2d }

  condition:
    any of them
}