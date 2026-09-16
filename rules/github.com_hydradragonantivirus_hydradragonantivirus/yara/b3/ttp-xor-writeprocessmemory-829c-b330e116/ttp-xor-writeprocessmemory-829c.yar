rule TTP_XOR_WriteProcessMemory_829c {
  strings:
    $key_829c = { d5 ee [2] e7 cc [2] e1 f9 [2] cf f9 [2] f0 e5 }

  condition:
    any of them
}