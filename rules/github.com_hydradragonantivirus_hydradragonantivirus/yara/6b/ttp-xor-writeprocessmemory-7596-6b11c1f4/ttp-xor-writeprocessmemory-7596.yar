rule TTP_XOR_WriteProcessMemory_7596 {
  strings:
    $key_7596 = { 22 e4 [2] 10 c6 [2] 16 f3 [2] 38 f3 [2] 07 ef }

  condition:
    any of them
}