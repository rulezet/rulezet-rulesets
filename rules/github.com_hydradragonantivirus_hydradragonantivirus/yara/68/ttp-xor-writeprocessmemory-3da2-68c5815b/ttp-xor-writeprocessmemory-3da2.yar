rule TTP_XOR_WriteProcessMemory_3da2 {
  strings:
    $key_3da2 = { 6a d0 [2] 58 f2 [2] 5e c7 [2] 70 c7 [2] 4f db }

  condition:
    any of them
}