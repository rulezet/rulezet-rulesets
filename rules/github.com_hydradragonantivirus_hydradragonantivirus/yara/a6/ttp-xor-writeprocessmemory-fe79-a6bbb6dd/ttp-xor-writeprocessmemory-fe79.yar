rule TTP_XOR_WriteProcessMemory_fe79 {
  strings:
    $key_fe79 = { a9 0b [2] 9b 29 [2] 9d 1c [2] b3 1c [2] 8c 00 }

  condition:
    any of them
}