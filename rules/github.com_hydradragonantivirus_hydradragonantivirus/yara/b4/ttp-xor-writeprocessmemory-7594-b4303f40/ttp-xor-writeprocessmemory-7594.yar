rule TTP_XOR_WriteProcessMemory_7594 {
  strings:
    $key_7594 = { 22 e6 [2] 10 c4 [2] 16 f1 [2] 38 f1 [2] 07 ed }

  condition:
    any of them
}