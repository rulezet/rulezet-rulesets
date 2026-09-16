rule TTP_XOR_WriteProcessMemory_fe19 {
  strings:
    $key_fe19 = { a9 6b [2] 9b 49 [2] 9d 7c [2] b3 7c [2] 8c 60 }

  condition:
    any of them
}