rule TTP_XOR_WriteProcessMemory_45a2 {
  strings:
    $key_45a2 = { 12 d0 [2] 20 f2 [2] 26 c7 [2] 08 c7 [2] 37 db }

  condition:
    any of them
}