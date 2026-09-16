rule TTP_XOR_WriteProcessMemory_8292 {
  strings:
    $key_8292 = { d5 e0 [2] e7 c2 [2] e1 f7 [2] cf f7 [2] f0 eb }

  condition:
    any of them
}