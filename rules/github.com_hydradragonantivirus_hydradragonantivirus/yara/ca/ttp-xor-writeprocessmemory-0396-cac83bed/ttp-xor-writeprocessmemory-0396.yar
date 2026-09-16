rule TTP_XOR_WriteProcessMemory_0396 {
  strings:
    $key_0396 = { 54 e4 [2] 66 c6 [2] 60 f3 [2] 4e f3 [2] 71 ef }

  condition:
    any of them
}