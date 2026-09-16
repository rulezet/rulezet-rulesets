rule TTP_XOR_WriteProcessMemory_fe15 {
  strings:
    $key_fe15 = { a9 67 [2] 9b 45 [2] 9d 70 [2] b3 70 [2] 8c 6c }

  condition:
    any of them
}