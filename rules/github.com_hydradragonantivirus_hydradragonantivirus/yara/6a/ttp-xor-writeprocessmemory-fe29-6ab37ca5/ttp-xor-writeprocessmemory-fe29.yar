rule TTP_XOR_WriteProcessMemory_fe29 {
  strings:
    $key_fe29 = { a9 5b [2] 9b 79 [2] 9d 4c [2] b3 4c [2] 8c 50 }

  condition:
    any of them
}