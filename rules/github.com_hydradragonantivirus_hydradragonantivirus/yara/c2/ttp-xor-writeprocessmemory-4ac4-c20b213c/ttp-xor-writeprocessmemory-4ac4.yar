rule TTP_XOR_WriteProcessMemory_4ac4 {
  strings:
    $key_4ac4 = { 1d b6 [2] 2f 94 [2] 29 a1 [2] 07 a1 [2] 38 bd }

  condition:
    any of them
}