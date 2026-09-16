rule TTP_XOR_WriteProcessMemory_6df7 {
  strings:
    $key_6df7 = { 3a 85 [2] 08 a7 [2] 0e 92 [2] 20 92 [2] 1f 8e }

  condition:
    any of them
}