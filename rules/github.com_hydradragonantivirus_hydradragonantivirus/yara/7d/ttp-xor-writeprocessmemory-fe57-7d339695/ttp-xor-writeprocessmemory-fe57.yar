rule TTP_XOR_WriteProcessMemory_fe57 {
  strings:
    $key_fe57 = { a9 25 [2] 9b 07 [2] 9d 32 [2] b3 32 [2] 8c 2e }

  condition:
    any of them
}