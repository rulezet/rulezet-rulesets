rule TTP_XOR_WriteProcessMemory_2ec5 {
  strings:
    $key_2ec5 = { 79 b7 [2] 4b 95 [2] 4d a0 [2] 63 a0 [2] 5c bc }

  condition:
    any of them
}