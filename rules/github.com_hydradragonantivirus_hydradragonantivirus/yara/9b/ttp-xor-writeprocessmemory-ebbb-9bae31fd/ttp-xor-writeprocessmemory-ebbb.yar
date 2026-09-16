rule TTP_XOR_WriteProcessMemory_ebbb {
  strings:
    $key_ebbb = { bc c9 [2] 8e eb [2] 88 de [2] a6 de [2] 99 c2 }

  condition:
    any of them
}