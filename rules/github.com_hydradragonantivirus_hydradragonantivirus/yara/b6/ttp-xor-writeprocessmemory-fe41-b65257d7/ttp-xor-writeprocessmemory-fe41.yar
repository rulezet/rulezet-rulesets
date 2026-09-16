rule TTP_XOR_WriteProcessMemory_fe41 {
  strings:
    $key_fe41 = { a9 33 [2] 9b 11 [2] 9d 24 [2] b3 24 [2] 8c 38 }

  condition:
    any of them
}