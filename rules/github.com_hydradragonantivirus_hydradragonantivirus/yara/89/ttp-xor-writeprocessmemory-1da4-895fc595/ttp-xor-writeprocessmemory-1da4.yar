rule TTP_XOR_WriteProcessMemory_1da4 {
  strings:
    $key_1da4 = { 4a d6 [2] 78 f4 [2] 7e c1 [2] 50 c1 [2] 6f dd }

  condition:
    any of them
}