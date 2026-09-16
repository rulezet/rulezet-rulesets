rule TTP_XOR_WriteProcessMemory_fe5d {
  strings:
    $key_fe5d = { a9 2f [2] 9b 0d [2] 9d 38 [2] b3 38 [2] 8c 24 }

  condition:
    any of them
}