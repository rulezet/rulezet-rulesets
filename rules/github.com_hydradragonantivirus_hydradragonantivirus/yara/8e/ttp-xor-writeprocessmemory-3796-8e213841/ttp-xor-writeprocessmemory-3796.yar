rule TTP_XOR_WriteProcessMemory_3796 {
  strings:
    $key_3796 = { 60 e4 [2] 52 c6 [2] 54 f3 [2] 7a f3 [2] 45 ef }

  condition:
    any of them
}