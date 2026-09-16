rule TTP_XOR_WriteProcessMemory_62a2 {
  strings:
    $key_62a2 = { 35 d0 [2] 07 f2 [2] 01 c7 [2] 2f c7 [2] 10 db }

  condition:
    any of them
}