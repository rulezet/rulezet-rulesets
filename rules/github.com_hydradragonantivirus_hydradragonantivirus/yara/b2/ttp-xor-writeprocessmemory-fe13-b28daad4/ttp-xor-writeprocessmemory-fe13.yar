rule TTP_XOR_WriteProcessMemory_fe13 {
  strings:
    $key_fe13 = { a9 61 [2] 9b 43 [2] 9d 76 [2] b3 76 [2] 8c 6a }

  condition:
    any of them
}