rule TTP_XOR_WriteProcessMemory_fe17 {
  strings:
    $key_fe17 = { a9 65 [2] 9b 47 [2] 9d 72 [2] b3 72 [2] 8c 6e }

  condition:
    any of them
}