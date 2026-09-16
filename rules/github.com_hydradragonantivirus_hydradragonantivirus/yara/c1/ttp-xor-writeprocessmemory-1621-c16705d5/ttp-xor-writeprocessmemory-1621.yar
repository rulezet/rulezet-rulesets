rule TTP_XOR_WriteProcessMemory_1621 {
  strings:
    $key_1621 = { 41 53 [2] 73 71 [2] 75 44 [2] 5b 44 [2] 64 58 }

  condition:
    any of them
}