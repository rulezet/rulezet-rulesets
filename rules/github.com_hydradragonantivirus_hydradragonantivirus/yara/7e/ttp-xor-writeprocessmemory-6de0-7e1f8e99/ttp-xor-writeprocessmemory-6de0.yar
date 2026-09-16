rule TTP_XOR_WriteProcessMemory_6de0 {
  strings:
    $key_6de0 = { 3a 92 [2] 08 b0 [2] 0e 85 [2] 20 85 [2] 1f 99 }

  condition:
    any of them
}