rule TTP_XOR_WriteProcessMemory_fe62 {
  strings:
    $key_fe62 = { a9 10 [2] 9b 32 [2] 9d 07 [2] b3 07 [2] 8c 1b }

  condition:
    any of them
}