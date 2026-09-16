rule TTP_XOR_WriteProcessMemory_f946 {
  strings:
    $key_f946 = { ae 34 [2] 9c 16 [2] 9a 23 [2] b4 23 [2] 8b 3f }

  condition:
    any of them
}