rule TTP_XOR_WriteProcessMemory_3794 {
  strings:
    $key_3794 = { 60 e6 [2] 52 c4 [2] 54 f1 [2] 7a f1 [2] 45 ed }

  condition:
    any of them
}