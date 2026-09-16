rule TTP_XOR_WriteProcessMemory_ebe7 {
  strings:
    $key_ebe7 = { bc 95 [2] 8e b7 [2] 88 82 [2] a6 82 [2] 99 9e }

  condition:
    any of them
}