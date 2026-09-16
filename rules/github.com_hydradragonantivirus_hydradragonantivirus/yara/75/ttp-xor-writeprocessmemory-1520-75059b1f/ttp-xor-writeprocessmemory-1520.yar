rule TTP_XOR_WriteProcessMemory_1520 {
  strings:
    $key_1520 = { 42 52 [2] 70 70 [2] 76 45 [2] 58 45 [2] 67 59 }

  condition:
    any of them
}