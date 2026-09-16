rule TTP_XOR_WriteProcessMemory_40d0 {
  strings:
    $key_40d0 = { 17 a2 [2] 25 80 [2] 23 b5 [2] 0d b5 [2] 32 a9 }

  condition:
    any of them
}