rule TTP_XOR_WriteProcessMemory_fe38 {
  strings:
    $key_fe38 = { a9 4a [2] 9b 68 [2] 9d 5d [2] b3 5d [2] 8c 41 }

  condition:
    any of them
}