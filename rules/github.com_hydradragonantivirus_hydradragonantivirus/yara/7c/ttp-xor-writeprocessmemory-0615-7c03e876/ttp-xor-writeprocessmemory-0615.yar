rule TTP_XOR_WriteProcessMemory_0615 {
  strings:
    $key_0615 = { 51 67 [2] 63 45 [2] 65 70 [2] 4b 70 [2] 74 6c }

  condition:
    any of them
}