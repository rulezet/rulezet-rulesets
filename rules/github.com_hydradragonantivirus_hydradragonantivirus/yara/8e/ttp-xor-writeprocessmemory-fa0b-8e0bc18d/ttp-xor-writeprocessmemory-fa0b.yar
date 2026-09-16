rule TTP_XOR_WriteProcessMemory_fa0b {
  strings:
    $key_fa0b = { ad 79 [2] 9f 5b [2] 99 6e [2] b7 6e [2] 88 72 }

  condition:
    any of them
}