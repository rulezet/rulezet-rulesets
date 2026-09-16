rule TTP_XOR_WriteProcessMemory_05b4 {
  strings:
    $key_05b4 = { 52 c6 [2] 60 e4 [2] 66 d1 [2] 48 d1 [2] 77 cd }

  condition:
    any of them
}