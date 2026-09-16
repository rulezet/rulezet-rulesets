rule TTP_XOR_WriteProcessMemory_7350 {
  strings:
    $key_7350 = { 24 22 [2] 16 00 [2] 10 35 [2] 3e 35 [2] 01 29 }

  condition:
    any of them
}