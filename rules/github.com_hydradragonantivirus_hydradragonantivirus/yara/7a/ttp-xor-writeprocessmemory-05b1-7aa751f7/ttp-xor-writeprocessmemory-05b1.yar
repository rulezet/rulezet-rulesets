rule TTP_XOR_WriteProcessMemory_05b1 {
  strings:
    $key_05b1 = { 52 c3 [2] 60 e1 [2] 66 d4 [2] 48 d4 [2] 77 c8 }

  condition:
    any of them
}