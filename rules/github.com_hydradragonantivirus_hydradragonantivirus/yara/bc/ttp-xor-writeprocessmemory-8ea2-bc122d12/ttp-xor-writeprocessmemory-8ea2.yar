rule TTP_XOR_WriteProcessMemory_8ea2 {
  strings:
    $key_8ea2 = { d9 d0 [2] eb f2 [2] ed c7 [2] c3 c7 [2] fc db }

  condition:
    any of them
}