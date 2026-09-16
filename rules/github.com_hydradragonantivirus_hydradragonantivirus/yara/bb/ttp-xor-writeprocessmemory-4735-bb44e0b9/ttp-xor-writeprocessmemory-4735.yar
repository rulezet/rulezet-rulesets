rule TTP_XOR_WriteProcessMemory_4735 {
  strings:
    $key_4735 = { 10 47 [2] 22 65 [2] 24 50 [2] 0a 50 [2] 35 4c }

  condition:
    any of them
}