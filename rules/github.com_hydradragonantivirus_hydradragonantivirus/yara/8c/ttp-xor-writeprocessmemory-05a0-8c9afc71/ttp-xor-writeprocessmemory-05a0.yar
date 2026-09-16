rule TTP_XOR_WriteProcessMemory_05a0 {
  strings:
    $key_05a0 = { 52 d2 [2] 60 f0 [2] 66 c5 [2] 48 c5 [2] 77 d9 }

  condition:
    any of them
}