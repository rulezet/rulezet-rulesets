rule TTP_XOR_WriteProcessMemory_8792 {
  strings:
    $key_8792 = { d0 e0 [2] e2 c2 [2] e4 f7 [2] ca f7 [2] f5 eb }

  condition:
    any of them
}