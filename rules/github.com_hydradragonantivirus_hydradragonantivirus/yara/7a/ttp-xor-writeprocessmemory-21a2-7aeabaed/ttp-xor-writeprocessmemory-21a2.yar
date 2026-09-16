rule TTP_XOR_WriteProcessMemory_21a2 {
  strings:
    $key_21a2 = { 76 d0 [2] 44 f2 [2] 42 c7 [2] 6c c7 [2] 53 db }

  condition:
    any of them
}