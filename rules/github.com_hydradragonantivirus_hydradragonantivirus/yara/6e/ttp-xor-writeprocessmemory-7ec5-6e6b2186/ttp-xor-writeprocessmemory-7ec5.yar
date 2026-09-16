rule TTP_XOR_WriteProcessMemory_7ec5 {
  strings:
    $key_7ec5 = { 29 b7 [2] 1b 95 [2] 1d a0 [2] 33 a0 [2] 0c bc }

  condition:
    any of them
}