rule TTP_XOR_WriteProcessMemory_7115 {
  strings:
    $key_7115 = { 26 67 [2] 14 45 [2] 12 70 [2] 3c 70 [2] 03 6c }

  condition:
    any of them
}