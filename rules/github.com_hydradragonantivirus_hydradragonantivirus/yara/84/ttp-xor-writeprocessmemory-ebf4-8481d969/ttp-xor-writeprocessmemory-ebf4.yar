rule TTP_XOR_WriteProcessMemory_ebf4 {
  strings:
    $key_ebf4 = { bc 86 [2] 8e a4 [2] 88 91 [2] a6 91 [2] 99 8d }

  condition:
    any of them
}