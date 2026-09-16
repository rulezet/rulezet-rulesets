rule TTP_XOR_WriteProcessMemory_6594 {
  strings:
    $key_6594 = { 32 e6 [2] 00 c4 [2] 06 f1 [2] 28 f1 [2] 17 ed }

  condition:
    any of them
}