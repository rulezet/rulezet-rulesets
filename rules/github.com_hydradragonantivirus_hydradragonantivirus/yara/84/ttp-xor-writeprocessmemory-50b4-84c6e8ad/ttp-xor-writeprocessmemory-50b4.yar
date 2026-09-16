rule TTP_XOR_WriteProcessMemory_50b4 {
  strings:
    $key_50b4 = { 07 c6 [2] 35 e4 [2] 33 d1 [2] 1d d1 [2] 22 cd }

  condition:
    any of them
}