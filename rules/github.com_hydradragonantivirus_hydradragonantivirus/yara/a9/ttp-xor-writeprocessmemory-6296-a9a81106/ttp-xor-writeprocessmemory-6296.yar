rule TTP_XOR_WriteProcessMemory_6296 {
  strings:
    $key_6296 = { 35 e4 [2] 07 c6 [2] 01 f3 [2] 2f f3 [2] 10 ef }

  condition:
    any of them
}