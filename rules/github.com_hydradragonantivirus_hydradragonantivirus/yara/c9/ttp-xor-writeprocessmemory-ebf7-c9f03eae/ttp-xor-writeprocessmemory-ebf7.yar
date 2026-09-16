rule TTP_XOR_WriteProcessMemory_ebf7 {
  strings:
    $key_ebf7 = { bc 85 [2] 8e a7 [2] 88 92 [2] a6 92 [2] 99 8e }

  condition:
    any of them
}