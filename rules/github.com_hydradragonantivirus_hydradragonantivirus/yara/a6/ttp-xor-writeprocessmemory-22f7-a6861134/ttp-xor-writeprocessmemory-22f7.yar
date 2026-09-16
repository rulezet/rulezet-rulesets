rule TTP_XOR_WriteProcessMemory_22f7 {
  strings:
    $key_22f7 = { 75 85 [2] 47 a7 [2] 41 92 [2] 6f 92 [2] 50 8e }

  condition:
    any of them
}