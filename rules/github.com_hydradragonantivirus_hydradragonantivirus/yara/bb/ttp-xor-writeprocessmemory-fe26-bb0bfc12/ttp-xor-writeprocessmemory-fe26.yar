rule TTP_XOR_WriteProcessMemory_fe26 {
  strings:
    $key_fe26 = { a9 54 [2] 9b 76 [2] 9d 43 [2] b3 43 [2] 8c 5f }

  condition:
    any of them
}