rule TTP_XOR_WriteProcessMemory_8290 {
  strings:
    $key_8290 = { d5 e2 [2] e7 c0 [2] e1 f5 [2] cf f5 [2] f0 e9 }

  condition:
    any of them
}