rule TTP_XOR_WriteProcessMemory_7165 {
  strings:
    $key_7165 = { 26 17 [2] 14 35 [2] 12 00 [2] 3c 00 [2] 03 1c }

  condition:
    any of them
}