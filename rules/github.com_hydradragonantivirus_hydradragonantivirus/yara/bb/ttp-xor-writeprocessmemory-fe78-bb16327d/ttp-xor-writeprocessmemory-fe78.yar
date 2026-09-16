rule TTP_XOR_WriteProcessMemory_fe78 {
  strings:
    $key_fe78 = { a9 0a [2] 9b 28 [2] 9d 1d [2] b3 1d [2] 8c 01 }

  condition:
    any of them
}