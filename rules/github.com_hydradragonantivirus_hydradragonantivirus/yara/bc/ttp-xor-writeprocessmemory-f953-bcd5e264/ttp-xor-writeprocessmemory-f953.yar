rule TTP_XOR_WriteProcessMemory_f953 {
  strings:
    $key_f953 = { ae 21 [2] 9c 03 [2] 9a 36 [2] b4 36 [2] 8b 2a }

  condition:
    any of them
}