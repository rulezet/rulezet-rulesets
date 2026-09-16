rule TTP_XOR_WriteProcessMemory_54a2 {
  strings:
    $key_54a2 = { 03 d0 [2] 31 f2 [2] 37 c7 [2] 19 c7 [2] 26 db }

  condition:
    any of them
}