rule TTP_XOR_WriteProcessMemory_fe6b {
  strings:
    $key_fe6b = { a9 19 [2] 9b 3b [2] 9d 0e [2] b3 0e [2] 8c 12 }

  condition:
    any of them
}