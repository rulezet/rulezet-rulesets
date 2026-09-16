rule TTP_XOR_WriteProcessMemory_62e0 {
  strings:
    $key_62e0 = { 35 92 [2] 07 b0 [2] 01 85 [2] 2f 85 [2] 10 99 }

  condition:
    any of them
}