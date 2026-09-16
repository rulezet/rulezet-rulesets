rule TTP_XOR_WriteProcessMemory_2615 {
  strings:
    $key_2615 = { 71 67 [2] 43 45 [2] 45 70 [2] 6b 70 [2] 54 6c }

  condition:
    any of them
}