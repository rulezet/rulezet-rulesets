rule TTP_XOR_WriteProcessMemory_1de0 {
  strings:
    $key_1de0 = { 4a 92 [2] 78 b0 [2] 7e 85 [2] 50 85 [2] 6f 99 }

  condition:
    any of them
}