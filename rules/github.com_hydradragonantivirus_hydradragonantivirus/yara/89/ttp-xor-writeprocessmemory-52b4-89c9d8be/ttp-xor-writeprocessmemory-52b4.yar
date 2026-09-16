rule TTP_XOR_WriteProcessMemory_52b4 {
  strings:
    $key_52b4 = { 05 c6 [2] 37 e4 [2] 31 d1 [2] 1f d1 [2] 20 cd }

  condition:
    any of them
}