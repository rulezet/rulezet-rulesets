rule TTP_XOR_WriteProcessMemory_1637 {
  strings:
    $key_1637 = { 41 45 [2] 73 67 [2] 75 52 [2] 5b 52 [2] 64 4e }

  condition:
    any of them
}