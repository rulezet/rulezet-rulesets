rule TTP_XOR_WriteProcessMemory_5515 {
  strings:
    $key_5515 = { 02 67 [2] 30 45 [2] 36 70 [2] 18 70 [2] 27 6c }

  condition:
    any of them
}