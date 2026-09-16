rule TTP_XOR_WriteProcessMemory_75d0 {
  strings:
    $key_75d0 = { 22 a2 [2] 10 80 [2] 16 b5 [2] 38 b5 [2] 07 a9 }

  condition:
    any of them
}