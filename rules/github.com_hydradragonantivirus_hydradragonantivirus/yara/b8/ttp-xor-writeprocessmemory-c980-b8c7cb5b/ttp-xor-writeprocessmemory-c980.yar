rule TTP_XOR_WriteProcessMemory_c980 {
  strings:
    $key_c980 = { 9e f2 [2] ac d0 [2] aa e5 [2] 84 e5 [2] bb f9 }

  condition:
    any of them
}