rule TTP_XOR_WriteProcessMemory_fe49 {
  strings:
    $key_fe49 = { a9 3b [2] 9b 19 [2] 9d 2c [2] b3 2c [2] 8c 30 }

  condition:
    any of them
}