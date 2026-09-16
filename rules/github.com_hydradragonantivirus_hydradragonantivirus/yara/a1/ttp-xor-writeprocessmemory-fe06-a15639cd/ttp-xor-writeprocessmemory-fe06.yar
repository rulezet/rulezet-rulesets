rule TTP_XOR_WriteProcessMemory_fe06 {
  strings:
    $key_fe06 = { a9 74 [2] 9b 56 [2] 9d 63 [2] b3 63 [2] 8c 7f }

  condition:
    any of them
}