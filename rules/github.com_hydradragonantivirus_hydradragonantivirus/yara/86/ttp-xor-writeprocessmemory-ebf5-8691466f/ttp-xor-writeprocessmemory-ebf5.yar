rule TTP_XOR_WriteProcessMemory_ebf5 {
  strings:
    $key_ebf5 = { bc 87 [2] 8e a5 [2] 88 90 [2] a6 90 [2] 99 8c }

  condition:
    any of them
}