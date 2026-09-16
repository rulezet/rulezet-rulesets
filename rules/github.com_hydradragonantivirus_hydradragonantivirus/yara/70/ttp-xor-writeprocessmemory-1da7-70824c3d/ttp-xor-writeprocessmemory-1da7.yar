rule TTP_XOR_WriteProcessMemory_1da7 {
  strings:
    $key_1da7 = { 4a d5 [2] 78 f7 [2] 7e c2 [2] 50 c2 [2] 6f de }

  condition:
    any of them
}