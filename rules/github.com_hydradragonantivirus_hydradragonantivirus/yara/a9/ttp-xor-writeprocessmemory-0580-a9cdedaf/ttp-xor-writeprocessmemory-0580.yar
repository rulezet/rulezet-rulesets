rule TTP_XOR_WriteProcessMemory_0580 {
  strings:
    $key_0580 = { 52 f2 [2] 60 d0 [2] 66 e5 [2] 48 e5 [2] 77 f9 }

  condition:
    any of them
}