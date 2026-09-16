rule TTP_XOR_WriteProcessMemory_a761 {
  strings:
    $key_a761 = { f0 13 [2] c2 31 [2] c4 04 [2] ea 04 [2] d5 18 }

  condition:
    any of them
}