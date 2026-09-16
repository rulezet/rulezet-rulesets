rule TTP_XOR_WriteProcessMemory_0796 {
  strings:
    $key_0796 = { 50 e4 [2] 62 c6 [2] 64 f3 [2] 4a f3 [2] 75 ef }

  condition:
    any of them
}