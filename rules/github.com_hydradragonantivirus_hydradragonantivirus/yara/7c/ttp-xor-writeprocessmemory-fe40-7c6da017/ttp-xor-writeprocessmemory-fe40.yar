rule TTP_XOR_WriteProcessMemory_fe40 {
  strings:
    $key_fe40 = { a9 32 [2] 9b 10 [2] 9d 25 [2] b3 25 [2] 8c 39 }

  condition:
    any of them
}