rule TTP_XOR_WriteProcessMemory_fa6b {
  strings:
    $key_fa6b = { ad 19 [2] 9f 3b [2] 99 0e [2] b7 0e [2] 88 12 }

  condition:
    any of them
}