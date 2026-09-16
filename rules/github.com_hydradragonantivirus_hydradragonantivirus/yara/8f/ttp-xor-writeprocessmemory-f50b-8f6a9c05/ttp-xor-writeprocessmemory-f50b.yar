rule TTP_XOR_WriteProcessMemory_f50b {
  strings:
    $key_f50b = { a2 79 [2] 90 5b [2] 96 6e [2] b8 6e [2] 87 72 }

  condition:
    any of them
}