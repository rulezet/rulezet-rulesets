rule TTP_XOR_WriteProcessMemory_8282 {
  strings:
    $key_8282 = { d5 f0 [2] e7 d2 [2] e1 e7 [2] cf e7 [2] f0 fb }

  condition:
    any of them
}