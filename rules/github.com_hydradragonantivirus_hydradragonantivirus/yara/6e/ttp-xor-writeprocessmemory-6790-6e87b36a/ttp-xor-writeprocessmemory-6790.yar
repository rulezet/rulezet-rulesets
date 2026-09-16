rule TTP_XOR_WriteProcessMemory_6790 {
  strings:
    $key_6790 = { 30 e2 [2] 02 c0 [2] 04 f5 [2] 2a f5 [2] 15 e9 }

  condition:
    any of them
}