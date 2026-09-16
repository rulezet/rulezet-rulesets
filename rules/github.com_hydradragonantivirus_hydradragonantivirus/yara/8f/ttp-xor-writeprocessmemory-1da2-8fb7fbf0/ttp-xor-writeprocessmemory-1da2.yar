rule TTP_XOR_WriteProcessMemory_1da2 {
  strings:
    $key_1da2 = { 4a d0 [2] 78 f2 [2] 7e c7 [2] 50 c7 [2] 6f db }

  condition:
    any of them
}