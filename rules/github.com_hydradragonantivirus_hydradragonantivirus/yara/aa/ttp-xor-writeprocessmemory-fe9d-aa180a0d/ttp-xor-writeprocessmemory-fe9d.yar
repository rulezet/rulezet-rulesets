rule TTP_XOR_WriteProcessMemory_fe9d {
  strings:
    $key_fe9d = { a9 ef [2] 9b cd [2] 9d f8 [2] b3 f8 [2] 8c e4 }

  condition:
    any of them
}