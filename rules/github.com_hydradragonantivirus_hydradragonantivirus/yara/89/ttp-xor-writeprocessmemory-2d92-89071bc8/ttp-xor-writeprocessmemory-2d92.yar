rule TTP_XOR_WriteProcessMemory_2d92 {
  strings:
    $key_2d92 = { 7a e0 [2] 48 c2 [2] 4e f7 [2] 60 f7 [2] 5f eb }

  condition:
    any of them
}