rule TTP_XOR_WriteProcessMemory_fe0b {
  strings:
    $key_fe0b = { a9 79 [2] 9b 5b [2] 9d 6e [2] b3 6e [2] 8c 72 }

  condition:
    any of them
}