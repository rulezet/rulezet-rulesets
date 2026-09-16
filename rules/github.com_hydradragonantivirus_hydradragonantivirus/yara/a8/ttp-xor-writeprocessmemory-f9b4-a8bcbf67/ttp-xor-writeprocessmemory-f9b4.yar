rule TTP_XOR_WriteProcessMemory_f9b4 {
  strings:
    $key_f9b4 = { ae c6 [2] 9c e4 [2] 9a d1 [2] b4 d1 [2] 8b cd }

  condition:
    any of them
}