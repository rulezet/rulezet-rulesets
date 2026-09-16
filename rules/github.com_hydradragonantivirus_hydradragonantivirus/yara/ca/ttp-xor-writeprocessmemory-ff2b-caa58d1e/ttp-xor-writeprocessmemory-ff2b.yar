rule TTP_XOR_WriteProcessMemory_ff2b {
  strings:
    $key_ff2b = { a8 59 [2] 9a 7b [2] 9c 4e [2] b2 4e [2] 8d 52 }

  condition:
    any of them
}