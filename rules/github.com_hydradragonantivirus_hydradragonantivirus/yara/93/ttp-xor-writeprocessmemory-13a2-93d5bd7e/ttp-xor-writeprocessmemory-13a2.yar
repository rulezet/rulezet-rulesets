rule TTP_XOR_WriteProcessMemory_13a2 {
  strings:
    $key_13a2 = { 44 d0 [2] 76 f2 [2] 70 c7 [2] 5e c7 [2] 61 db }

  condition:
    any of them
}