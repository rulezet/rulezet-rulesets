rule TTP_XOR_WriteProcessMemory_75c4 {
  strings:
    $key_75c4 = { 22 b6 [2] 10 94 [2] 16 a1 [2] 38 a1 [2] 07 bd }

  condition:
    any of them
}