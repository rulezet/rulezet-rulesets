rule TTP_XOR_WriteProcessMemory_f956 {
  strings:
    $key_f956 = { ae 24 [2] 9c 06 [2] 9a 33 [2] b4 33 [2] 8b 2f }

  condition:
    any of them
}