rule TTP_XOR_WriteProcessMemory_07a2 {
  strings:
    $key_07a2 = { 50 d0 [2] 62 f2 [2] 64 c7 [2] 4a c7 [2] 75 db }

  condition:
    any of them
}