rule TTP_XOR_WriteProcessMemory_6490 {
  strings:
    $key_6490 = { 33 e2 [2] 01 c0 [2] 07 f5 [2] 29 f5 [2] 16 e9 }

  condition:
    any of them
}