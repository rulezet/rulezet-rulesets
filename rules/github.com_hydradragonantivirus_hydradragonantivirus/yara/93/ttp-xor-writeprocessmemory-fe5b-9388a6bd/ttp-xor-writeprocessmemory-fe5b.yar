rule TTP_XOR_WriteProcessMemory_fe5b {
  strings:
    $key_fe5b = { a9 29 [2] 9b 0b [2] 9d 3e [2] b3 3e [2] 8c 22 }

  condition:
    any of them
}