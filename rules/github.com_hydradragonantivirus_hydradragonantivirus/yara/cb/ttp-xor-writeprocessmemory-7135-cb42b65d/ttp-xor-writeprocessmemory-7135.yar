rule TTP_XOR_WriteProcessMemory_7135 {
  strings:
    $key_7135 = { 26 47 [2] 14 65 [2] 12 50 [2] 3c 50 [2] 03 4c }

  condition:
    any of them
}