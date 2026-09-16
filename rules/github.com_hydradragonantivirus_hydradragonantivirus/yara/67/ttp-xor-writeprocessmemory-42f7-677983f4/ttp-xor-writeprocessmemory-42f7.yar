rule TTP_XOR_WriteProcessMemory_42f7 {
  strings:
    $key_42f7 = { 15 85 [2] 27 a7 [2] 21 92 [2] 0f 92 [2] 30 8e }

  condition:
    any of them
}