rule TTP_XOR_WriteProcessMemory_08f7 {
  strings:
    $key_08f7 = { 5f 85 [2] 6d a7 [2] 6b 92 [2] 45 92 [2] 7a 8e }

  condition:
    any of them
}