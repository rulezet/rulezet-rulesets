rule TTP_XOR_WriteProcessMemory_fe2b {
  strings:
    $key_fe2b = { a9 59 [2] 9b 7b [2] 9d 4e [2] b3 4e [2] 8c 52 }

  condition:
    any of them
}