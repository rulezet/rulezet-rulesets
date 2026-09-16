rule TTP_XOR_WriteProcessMemory_ff1b {
  strings:
    $key_ff1b = { a8 69 [2] 9a 4b [2] 9c 7e [2] b2 7e [2] 8d 62 }

  condition:
    any of them
}