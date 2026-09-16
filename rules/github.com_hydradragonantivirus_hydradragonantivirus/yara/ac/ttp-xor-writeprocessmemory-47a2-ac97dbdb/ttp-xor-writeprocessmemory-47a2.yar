rule TTP_XOR_WriteProcessMemory_47a2 {
  strings:
    $key_47a2 = { 10 d0 [2] 22 f2 [2] 24 c7 [2] 0a c7 [2] 35 db }

  condition:
    any of them
}