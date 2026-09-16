rule TTP_XOR_WriteProcessMemory_69e0 {
  strings:
    $key_69e0 = { 3e 92 [2] 0c b0 [2] 0a 85 [2] 24 85 [2] 1b 99 }

  condition:
    any of them
}