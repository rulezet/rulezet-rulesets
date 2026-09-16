rule TTP_XOR_WriteProcessMemory_44b4 {
  strings:
    $key_44b4 = { 13 c6 [2] 21 e4 [2] 27 d1 [2] 09 d1 [2] 36 cd }

  condition:
    any of them
}