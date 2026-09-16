rule TTP_XOR_WriteProcessMemory_ebec {
  strings:
    $key_ebec = { bc 9e [2] 8e bc [2] 88 89 [2] a6 89 [2] 99 95 }

  condition:
    any of them
}