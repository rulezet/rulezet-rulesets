rule TTP_XOR_WriteProcessMemory_6da2 {
  strings:
    $key_6da2 = { 3a d0 [2] 08 f2 [2] 0e c7 [2] 20 c7 [2] 1f db }

  condition:
    any of them
}