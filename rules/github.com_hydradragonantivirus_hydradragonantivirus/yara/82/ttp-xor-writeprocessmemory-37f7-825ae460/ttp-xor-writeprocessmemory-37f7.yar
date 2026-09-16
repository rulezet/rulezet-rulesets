rule TTP_XOR_WriteProcessMemory_37f7 {
  strings:
    $key_37f7 = { 60 85 [2] 52 a7 [2] 54 92 [2] 7a 92 [2] 45 8e }

  condition:
    any of them
}