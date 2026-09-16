rule TTP_XOR_WriteProcessMemory_7722 {
  strings:
    $key_7722 = { 20 50 [2] 12 72 [2] 14 47 [2] 3a 47 [2] 05 5b }

  condition:
    any of them
}