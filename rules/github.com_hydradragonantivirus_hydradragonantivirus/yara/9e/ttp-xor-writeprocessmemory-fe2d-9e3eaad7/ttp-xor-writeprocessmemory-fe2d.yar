rule TTP_XOR_WriteProcessMemory_fe2d {
  strings:
    $key_fe2d = { a9 5f [2] 9b 7d [2] 9d 48 [2] b3 48 [2] 8c 54 }

  condition:
    any of them
}