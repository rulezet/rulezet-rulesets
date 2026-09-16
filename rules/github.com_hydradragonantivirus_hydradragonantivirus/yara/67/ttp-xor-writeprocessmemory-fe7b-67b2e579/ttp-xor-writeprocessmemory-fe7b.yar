rule TTP_XOR_WriteProcessMemory_fe7b {
  strings:
    $key_fe7b = { a9 09 [2] 9b 2b [2] 9d 1e [2] b3 1e [2] 8c 02 }

  condition:
    any of them
}