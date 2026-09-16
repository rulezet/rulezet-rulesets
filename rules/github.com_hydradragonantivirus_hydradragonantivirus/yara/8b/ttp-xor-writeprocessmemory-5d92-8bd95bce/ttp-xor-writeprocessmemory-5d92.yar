rule TTP_XOR_WriteProcessMemory_5d92 {
  strings:
    $key_5d92 = { 0a e0 [2] 38 c2 [2] 3e f7 [2] 10 f7 [2] 2f eb }

  condition:
    any of them
}