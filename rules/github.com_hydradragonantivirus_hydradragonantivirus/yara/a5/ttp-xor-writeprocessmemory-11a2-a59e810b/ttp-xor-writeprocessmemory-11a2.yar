rule TTP_XOR_WriteProcessMemory_11a2 {
  strings:
    $key_11a2 = { 46 d0 [2] 74 f2 [2] 72 c7 [2] 5c c7 [2] 63 db }

  condition:
    any of them
}