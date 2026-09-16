rule TTP_XOR_WriteProcessMemory_fe70 {
  strings:
    $key_fe70 = { a9 02 [2] 9b 20 [2] 9d 15 [2] b3 15 [2] 8c 09 }

  condition:
    any of them
}