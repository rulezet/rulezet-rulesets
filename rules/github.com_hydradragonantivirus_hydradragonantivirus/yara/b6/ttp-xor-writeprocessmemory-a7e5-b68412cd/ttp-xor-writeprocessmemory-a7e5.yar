rule TTP_XOR_WriteProcessMemory_a7e5 {
  strings:
    $key_a7e5 = { f0 97 [2] c2 b5 [2] c4 80 [2] ea 80 [2] d5 9c }

  condition:
    any of them
}