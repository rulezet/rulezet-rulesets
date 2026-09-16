rule TTP_XOR_WriteProcessMemory_1f85 {
  strings:
    $key_1f85 = { 48 f7 [2] 7a d5 [2] 7c e0 [2] 52 e0 [2] 6d fc }

  condition:
    any of them
}