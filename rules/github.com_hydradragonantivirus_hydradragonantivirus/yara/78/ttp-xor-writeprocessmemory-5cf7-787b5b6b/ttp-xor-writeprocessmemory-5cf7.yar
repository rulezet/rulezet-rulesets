rule TTP_XOR_WriteProcessMemory_5cf7 {
  strings:
    $key_5cf7 = { 0b 85 [2] 39 a7 [2] 3f 92 [2] 11 92 [2] 2e 8e }

  condition:
    any of them
}