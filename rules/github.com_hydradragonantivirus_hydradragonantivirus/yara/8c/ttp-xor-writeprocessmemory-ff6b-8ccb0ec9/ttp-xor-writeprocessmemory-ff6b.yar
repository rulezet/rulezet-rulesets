rule TTP_XOR_WriteProcessMemory_ff6b {
  strings:
    $key_ff6b = { a8 19 [2] 9a 3b [2] 9c 0e [2] b2 0e [2] 8d 12 }

  condition:
    any of them
}