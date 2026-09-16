rule TTP_XOR_WriteProcessMemory_5615 {
  strings:
    $key_5615 = { 01 67 [2] 33 45 [2] 35 70 [2] 1b 70 [2] 24 6c }

  condition:
    any of them
}