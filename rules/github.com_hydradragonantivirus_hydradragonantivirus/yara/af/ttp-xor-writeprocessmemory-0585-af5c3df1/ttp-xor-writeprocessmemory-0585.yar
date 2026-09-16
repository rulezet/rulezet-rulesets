rule TTP_XOR_WriteProcessMemory_0585 {
  strings:
    $key_0585 = { 52 f7 [2] 60 d5 [2] 66 e0 [2] 48 e0 [2] 77 fc }

  condition:
    any of them
}