rule TTP_XOR_WriteProcessMemory_5594 {
  strings:
    $key_5594 = { 02 e6 [2] 30 c4 [2] 36 f1 [2] 18 f1 [2] 27 ed }

  condition:
    any of them
}