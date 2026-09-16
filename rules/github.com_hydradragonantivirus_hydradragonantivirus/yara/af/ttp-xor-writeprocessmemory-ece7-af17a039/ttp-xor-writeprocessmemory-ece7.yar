rule TTP_XOR_WriteProcessMemory_ece7 {
  strings:
    $key_ece7 = { bb 95 [2] 89 b7 [2] 8f 82 [2] a1 82 [2] 9e 9e }

  condition:
    any of them
}