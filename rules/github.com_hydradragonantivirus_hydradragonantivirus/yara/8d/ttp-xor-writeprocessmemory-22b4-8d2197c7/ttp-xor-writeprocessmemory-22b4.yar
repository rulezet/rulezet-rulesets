rule TTP_XOR_WriteProcessMemory_22b4 {
  strings:
    $key_22b4 = { 75 c6 [2] 47 e4 [2] 41 d1 [2] 6f d1 [2] 50 cd }

  condition:
    any of them
}