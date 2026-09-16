rule TTP_XOR_WriteProcessMemory_3396 {
  strings:
    $key_3396 = { 64 e4 [2] 56 c6 [2] 50 f3 [2] 7e f3 [2] 41 ef }

  condition:
    any of them
}