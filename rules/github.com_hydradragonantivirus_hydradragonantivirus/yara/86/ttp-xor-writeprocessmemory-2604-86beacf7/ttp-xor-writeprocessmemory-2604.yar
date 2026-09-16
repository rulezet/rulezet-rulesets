rule TTP_XOR_WriteProcessMemory_2604 {
  strings:
    $key_2604 = { 71 76 [2] 43 54 [2] 45 61 [2] 6b 61 [2] 54 7d }

  condition:
    any of them
}