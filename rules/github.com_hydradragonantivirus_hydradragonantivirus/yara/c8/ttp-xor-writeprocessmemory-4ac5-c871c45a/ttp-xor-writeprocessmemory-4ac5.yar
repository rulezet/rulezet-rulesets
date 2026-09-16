rule TTP_XOR_WriteProcessMemory_4ac5 {
  strings:
    $key_4ac5 = { 1d b7 [2] 2f 95 [2] 29 a0 [2] 07 a0 [2] 38 bc }

  condition:
    any of them
}