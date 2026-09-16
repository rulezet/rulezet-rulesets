rule TTP_XOR_WriteProcessMemory_0521 {
  strings:
    $key_0521 = { 52 53 [2] 60 71 [2] 66 44 [2] 48 44 [2] 77 58 }

  condition:
    any of them
}