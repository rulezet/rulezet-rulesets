rule TTP_XOR_WriteProcessMemory_fe3d {
  strings:
    $key_fe3d = { a9 4f [2] 9b 6d [2] 9d 58 [2] b3 58 [2] 8c 44 }

  condition:
    any of them
}