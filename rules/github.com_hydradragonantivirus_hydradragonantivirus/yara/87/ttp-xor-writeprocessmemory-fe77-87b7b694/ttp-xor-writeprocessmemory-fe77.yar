rule TTP_XOR_WriteProcessMemory_fe77 {
  strings:
    $key_fe77 = { a9 05 [2] 9b 27 [2] 9d 12 [2] b3 12 [2] 8c 0e }

  condition:
    any of them
}