rule TTP_XOR_WriteProcessMemory_fe00 {
  strings:
    $key_fe00 = { a9 72 [2] 9b 50 [2] 9d 65 [2] b3 65 [2] 8c 79 }

  condition:
    any of them
}