rule TTP_XOR_WriteProcessMemory_fe28 {
  strings:
    $key_fe28 = { a9 5a [2] 9b 78 [2] 9d 4d [2] b3 4d [2] 8c 51 }

  condition:
    any of them
}