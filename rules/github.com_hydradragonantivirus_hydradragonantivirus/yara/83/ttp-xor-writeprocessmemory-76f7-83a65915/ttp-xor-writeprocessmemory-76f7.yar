rule TTP_XOR_WriteProcessMemory_76f7 {
  strings:
    $key_76f7 = { 21 85 [2] 13 a7 [2] 15 92 [2] 3b 92 [2] 04 8e }

  condition:
    any of them
}