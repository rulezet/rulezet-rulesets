rule TTP_XOR_WriteProcessMemory_79e0 {
  strings:
    $key_79e0 = { 2e 92 [2] 1c b0 [2] 1a 85 [2] 34 85 [2] 0b 99 }

  condition:
    any of them
}