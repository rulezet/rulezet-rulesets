rule TTP_XOR_WriteProcessMemory_45f7 {
  strings:
    $key_45f7 = { 12 85 [2] 20 a7 [2] 26 92 [2] 08 92 [2] 37 8e }

  condition:
    any of them
}