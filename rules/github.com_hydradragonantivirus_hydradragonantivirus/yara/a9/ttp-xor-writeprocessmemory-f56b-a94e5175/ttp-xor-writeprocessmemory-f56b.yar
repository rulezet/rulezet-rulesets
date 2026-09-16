rule TTP_XOR_WriteProcessMemory_f56b {
  strings:
    $key_f56b = { a2 19 [2] 90 3b [2] 96 0e [2] b8 0e [2] 87 12 }

  condition:
    any of them
}