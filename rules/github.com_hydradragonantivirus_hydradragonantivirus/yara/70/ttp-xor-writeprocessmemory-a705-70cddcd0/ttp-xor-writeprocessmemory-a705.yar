rule TTP_XOR_WriteProcessMemory_a705 {
  strings:
    $key_a705 = { f0 77 [2] c2 55 [2] c4 60 [2] ea 60 [2] d5 7c }

  condition:
    any of them
}