rule TTP_XOR_WriteProcessMemory_fe45 {
  strings:
    $key_fe45 = { a9 37 [2] 9b 15 [2] 9d 20 [2] b3 20 [2] 8c 3c }

  condition:
    any of them
}