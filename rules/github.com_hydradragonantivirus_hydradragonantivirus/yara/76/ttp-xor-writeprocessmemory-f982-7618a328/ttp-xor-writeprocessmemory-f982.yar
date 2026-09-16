rule TTP_XOR_WriteProcessMemory_f982 {
  strings:
    $key_f982 = { ae f0 [2] 9c d2 [2] 9a e7 [2] b4 e7 [2] 8b fb }

  condition:
    any of them
}