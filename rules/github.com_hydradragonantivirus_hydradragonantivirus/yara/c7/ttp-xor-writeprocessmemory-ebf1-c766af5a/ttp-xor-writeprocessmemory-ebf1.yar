rule TTP_XOR_WriteProcessMemory_ebf1 {
  strings:
    $key_ebf1 = { bc 83 [2] 8e a1 [2] 88 94 [2] a6 94 [2] 99 88 }

  condition:
    any of them
}