rule TTP_XOR_WriteProcessMemory_859c {
  strings:
    $key_859c = { d2 ee [2] e0 cc [2] e6 f9 [2] c8 f9 [2] f7 e5 }

  condition:
    any of them
}