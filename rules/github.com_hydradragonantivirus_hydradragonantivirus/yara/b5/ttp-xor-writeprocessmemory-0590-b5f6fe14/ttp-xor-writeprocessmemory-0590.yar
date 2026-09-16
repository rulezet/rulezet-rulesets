rule TTP_XOR_WriteProcessMemory_0590 {
  strings:
    $key_0590 = { 52 e2 [2] 60 c0 [2] 66 f5 [2] 48 f5 [2] 77 e9 }

  condition:
    any of them
}