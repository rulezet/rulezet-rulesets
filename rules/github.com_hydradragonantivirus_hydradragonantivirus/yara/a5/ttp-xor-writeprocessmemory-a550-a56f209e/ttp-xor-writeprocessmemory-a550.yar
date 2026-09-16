rule TTP_XOR_WriteProcessMemory_a550 {
  strings:
    $key_a550 = { f2 22 [2] c0 00 [2] c6 35 [2] e8 35 [2] d7 29 }

  condition:
    any of them
}