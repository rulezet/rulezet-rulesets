rule TTP_XOR_WriteProcessMemory_1537 {
  strings:
    $key_1537 = { 42 45 [2] 70 67 [2] 76 52 [2] 58 52 [2] 67 4e }

  condition:
    any of them
}