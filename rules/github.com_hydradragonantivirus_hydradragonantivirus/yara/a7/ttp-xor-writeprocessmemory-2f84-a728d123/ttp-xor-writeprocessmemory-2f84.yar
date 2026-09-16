rule TTP_XOR_WriteProcessMemory_2f84 {
  strings:
    $key_2f84 = { 78 f6 [2] 4a d4 [2] 4c e1 [2] 62 e1 [2] 5d fd }

  condition:
    any of them
}