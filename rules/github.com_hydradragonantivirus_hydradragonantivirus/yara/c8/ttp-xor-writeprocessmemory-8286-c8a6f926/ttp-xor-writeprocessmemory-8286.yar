rule TTP_XOR_WriteProcessMemory_8286 {
  strings:
    $key_8286 = { d5 f4 [2] e7 d6 [2] e1 e3 [2] cf e3 [2] f0 ff }

  condition:
    any of them
}