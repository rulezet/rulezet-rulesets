rule TTP_XOR_WriteProcessMemory_fe0d {
  strings:
    $key_fe0d = { a9 7f [2] 9b 5d [2] 9d 68 [2] b3 68 [2] 8c 74 }

  condition:
    any of them
}