rule TTP_XOR_WriteProcessMemory_fe91 {
  strings:
    $key_fe91 = { a9 e3 [2] 9b c1 [2] 9d f4 [2] b3 f4 [2] 8c e8 }

  condition:
    any of them
}