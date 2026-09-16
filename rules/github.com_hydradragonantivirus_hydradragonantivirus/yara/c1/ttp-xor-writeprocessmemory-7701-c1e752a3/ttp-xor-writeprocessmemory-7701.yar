rule TTP_XOR_WriteProcessMemory_7701 {
  strings:
    $key_7701 = { 20 73 [2] 12 51 [2] 14 64 [2] 3a 64 [2] 05 78 }

  condition:
    any of them
}