rule TTP_XOR_WriteProcessMemory_45c4 {
  strings:
    $key_45c4 = { 12 b6 [2] 20 94 [2] 26 a1 [2] 08 a1 [2] 37 bd }

  condition:
    any of them
}