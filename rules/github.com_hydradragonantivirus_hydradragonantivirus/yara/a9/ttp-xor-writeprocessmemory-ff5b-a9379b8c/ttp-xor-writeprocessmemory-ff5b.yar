rule TTP_XOR_WriteProcessMemory_ff5b {
  strings:
    $key_ff5b = { a8 29 [2] 9a 0b [2] 9c 3e [2] b2 3e [2] 8d 22 }

  condition:
    any of them
}