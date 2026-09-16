rule TTP_XOR_WriteProcessMemory_f984 {
  strings:
    $key_f984 = { ae f6 [2] 9c d4 [2] 9a e1 [2] b4 e1 [2] 8b fd }

  condition:
    any of them
}