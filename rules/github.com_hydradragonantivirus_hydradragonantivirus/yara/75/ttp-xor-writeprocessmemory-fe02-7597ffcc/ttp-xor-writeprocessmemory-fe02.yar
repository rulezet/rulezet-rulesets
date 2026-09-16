rule TTP_XOR_WriteProcessMemory_fe02 {
  strings:
    $key_fe02 = { a9 70 [2] 9b 52 [2] 9d 67 [2] b3 67 [2] 8c 7b }

  condition:
    any of them
}