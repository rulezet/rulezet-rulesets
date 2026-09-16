rule TTP_XOR_WriteProcessMemory_8285 {
  strings:
    $key_8285 = { d5 f7 [2] e7 d5 [2] e1 e0 [2] cf e0 [2] f0 fc }

  condition:
    any of them
}