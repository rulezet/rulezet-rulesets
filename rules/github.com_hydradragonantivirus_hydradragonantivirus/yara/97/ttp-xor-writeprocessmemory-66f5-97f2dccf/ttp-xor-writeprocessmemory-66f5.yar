rule TTP_XOR_WriteProcessMemory_66f5 {
  strings:
    $key_66f5 = { 31 87 [2] 03 a5 [2] 05 90 [2] 2b 90 [2] 14 8c }

  condition:
    any of them
}