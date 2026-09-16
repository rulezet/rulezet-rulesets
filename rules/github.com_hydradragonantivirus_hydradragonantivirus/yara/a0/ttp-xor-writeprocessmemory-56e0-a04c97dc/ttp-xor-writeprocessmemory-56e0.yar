rule TTP_XOR_WriteProcessMemory_56e0 {
  strings:
    $key_56e0 = { 01 92 [2] 33 b0 [2] 35 85 [2] 1b 85 [2] 24 99 }

  condition:
    any of them
}