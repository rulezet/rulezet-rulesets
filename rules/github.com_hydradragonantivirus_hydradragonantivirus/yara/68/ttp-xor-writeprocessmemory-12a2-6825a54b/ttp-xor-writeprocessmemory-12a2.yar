rule TTP_XOR_WriteProcessMemory_12a2 {
  strings:
    $key_12a2 = { 45 d0 [2] 77 f2 [2] 71 c7 [2] 5f c7 [2] 60 db }

  condition:
    any of them
}