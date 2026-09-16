rule TTP_XOR_WriteProcessMemory_1661 {
  strings:
    $key_1661 = { 41 13 [2] 73 31 [2] 75 04 [2] 5b 04 [2] 64 18 }

  condition:
    any of them
}