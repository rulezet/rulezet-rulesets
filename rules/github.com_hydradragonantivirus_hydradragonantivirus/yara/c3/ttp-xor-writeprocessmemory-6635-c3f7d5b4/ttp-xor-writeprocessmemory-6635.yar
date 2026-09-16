rule TTP_XOR_WriteProcessMemory_6635 {
  strings:
    $key_6635 = { 31 47 [2] 03 65 [2] 05 50 [2] 2b 50 [2] 14 4c }

  condition:
    any of them
}