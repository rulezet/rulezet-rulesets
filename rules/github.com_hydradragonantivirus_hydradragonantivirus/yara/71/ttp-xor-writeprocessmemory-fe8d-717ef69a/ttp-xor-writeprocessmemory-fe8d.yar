rule TTP_XOR_WriteProcessMemory_fe8d {
  strings:
    $key_fe8d = { a9 ff [2] 9b dd [2] 9d e8 [2] b3 e8 [2] 8c f4 }

  condition:
    any of them
}