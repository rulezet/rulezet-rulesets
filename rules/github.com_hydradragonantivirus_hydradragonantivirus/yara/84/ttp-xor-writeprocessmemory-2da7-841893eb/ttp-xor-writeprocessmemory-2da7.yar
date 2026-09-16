rule TTP_XOR_WriteProcessMemory_2da7 {
  strings:
    $key_2da7 = { 7a d5 [2] 48 f7 [2] 4e c2 [2] 60 c2 [2] 5f de }

  condition:
    any of them
}