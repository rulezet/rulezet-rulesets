rule TTP_XOR_WriteProcessMemory_37f5 {
  strings:
    $key_37f5 = { 60 87 [2] 52 a5 [2] 54 90 [2] 7a 90 [2] 45 8c }

  condition:
    any of them
}