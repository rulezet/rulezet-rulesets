rule TTP_XOR_WriteProcessMemory_0591 {
  strings:
    $key_0591 = { 52 e3 [2] 60 c1 [2] 66 f4 [2] 48 f4 [2] 77 e8 }

  condition:
    any of them
}