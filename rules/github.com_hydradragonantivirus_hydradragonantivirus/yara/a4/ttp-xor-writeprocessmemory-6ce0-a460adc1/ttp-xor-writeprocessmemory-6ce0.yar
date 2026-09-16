rule TTP_XOR_WriteProcessMemory_6ce0 {
  strings:
    $key_6ce0 = { 3b 92 [2] 09 b0 [2] 0f 85 [2] 21 85 [2] 1e 99 }

  condition:
    any of them
}