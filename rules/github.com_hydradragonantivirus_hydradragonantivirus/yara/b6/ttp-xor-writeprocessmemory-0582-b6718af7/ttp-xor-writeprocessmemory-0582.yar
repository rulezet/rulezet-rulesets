rule TTP_XOR_WriteProcessMemory_0582 {
  strings:
    $key_0582 = { 52 f0 [2] 60 d2 [2] 66 e7 [2] 48 e7 [2] 77 fb }

  condition:
    any of them
}