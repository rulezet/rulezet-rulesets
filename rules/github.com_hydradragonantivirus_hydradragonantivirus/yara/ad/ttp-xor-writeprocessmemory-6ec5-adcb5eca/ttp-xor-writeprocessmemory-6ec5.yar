rule TTP_XOR_WriteProcessMemory_6ec5 {
  strings:
    $key_6ec5 = { 39 b7 [2] 0b 95 [2] 0d a0 [2] 23 a0 [2] 1c bc }

  condition:
    any of them
}