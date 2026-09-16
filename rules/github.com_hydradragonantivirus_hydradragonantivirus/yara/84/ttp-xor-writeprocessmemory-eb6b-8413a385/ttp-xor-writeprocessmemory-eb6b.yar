rule TTP_XOR_WriteProcessMemory_eb6b {
  strings:
    $key_eb6b = { bc 19 [2] 8e 3b [2] 88 0e [2] a6 0e [2] 99 12 }

  condition:
    any of them
}