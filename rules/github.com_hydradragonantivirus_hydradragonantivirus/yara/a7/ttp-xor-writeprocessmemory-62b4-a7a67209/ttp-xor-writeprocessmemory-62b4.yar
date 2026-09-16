rule TTP_XOR_WriteProcessMemory_62b4 {
  strings:
    $key_62b4 = { 35 c6 [2] 07 e4 [2] 01 d1 [2] 2f d1 [2] 10 cd }

  condition:
    any of them
}