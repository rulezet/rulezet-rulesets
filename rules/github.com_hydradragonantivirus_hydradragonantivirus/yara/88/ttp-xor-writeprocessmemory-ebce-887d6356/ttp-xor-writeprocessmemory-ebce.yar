rule TTP_XOR_WriteProcessMemory_ebce {
  strings:
    $key_ebce = { bc bc [2] 8e 9e [2] 88 ab [2] a6 ab [2] 99 b7 }

  condition:
    any of them
}