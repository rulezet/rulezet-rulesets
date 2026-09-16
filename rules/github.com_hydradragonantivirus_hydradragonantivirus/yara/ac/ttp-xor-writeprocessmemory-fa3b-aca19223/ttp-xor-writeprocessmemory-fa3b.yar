rule TTP_XOR_WriteProcessMemory_fa3b {
  strings:
    $key_fa3b = { ad 49 [2] 9f 6b [2] 99 5e [2] b7 5e [2] 88 42 }

  condition:
    any of them
}