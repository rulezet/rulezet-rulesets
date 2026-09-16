rule TTP_XOR_WriteProcessMemory_73a2 {
  strings:
    $key_73a2 = { 24 d0 [2] 16 f2 [2] 10 c7 [2] 3e c7 [2] 01 db }

  condition:
    any of them
}