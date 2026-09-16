rule TTP_XOR_WriteProcessMemory_fe36 {
  strings:
    $key_fe36 = { a9 44 [2] 9b 66 [2] 9d 53 [2] b3 53 [2] 8c 4f }

  condition:
    any of them
}