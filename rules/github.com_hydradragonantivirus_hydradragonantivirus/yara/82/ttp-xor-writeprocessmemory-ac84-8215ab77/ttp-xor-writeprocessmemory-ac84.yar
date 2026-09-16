rule TTP_XOR_WriteProcessMemory_ac84 {
  strings:
    $key_ac84 = { fb f6 [2] c9 d4 [2] cf e1 [2] e1 e1 [2] de fd }

  condition:
    any of them
}