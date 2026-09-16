rule TTP_XOR_WriteProcessMemory_fe61 {
  strings:
    $key_fe61 = { a9 13 [2] 9b 31 [2] 9d 04 [2] b3 04 [2] 8c 18 }

  condition:
    any of them
}