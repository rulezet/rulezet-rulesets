rule TTP_XOR_WriteProcessMemory_6491 {
  strings:
    $key_6491 = { 33 e3 [2] 01 c1 [2] 07 f4 [2] 29 f4 [2] 16 e8 }

  condition:
    any of them
}