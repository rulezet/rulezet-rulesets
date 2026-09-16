rule TTP_XOR_WriteProcessMemory_21e0 {
  strings:
    $key_21e0 = { 76 92 [2] 44 b0 [2] 42 85 [2] 6c 85 [2] 53 99 }

  condition:
    any of them
}