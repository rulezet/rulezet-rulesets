rule TTP_XOR_WriteProcessMemory_fe08 {
  strings:
    $key_fe08 = { a9 7a [2] 9b 58 [2] 9d 6d [2] b3 6d [2] 8c 71 }

  condition:
    any of them
}