rule TTP_XOR_WriteProcessMemory_4a97 {
  strings:
    $key_4a97 = { 1d e5 [2] 2f c7 [2] 29 f2 [2] 07 f2 [2] 38 ee }

  condition:
    any of them
}