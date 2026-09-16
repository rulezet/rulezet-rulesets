rule TTP_XOR_WriteProcessMemory_fe71 {
  strings:
    $key_fe71 = { a9 03 [2] 9b 21 [2] 9d 14 [2] b3 14 [2] 8c 08 }

  condition:
    any of them
}