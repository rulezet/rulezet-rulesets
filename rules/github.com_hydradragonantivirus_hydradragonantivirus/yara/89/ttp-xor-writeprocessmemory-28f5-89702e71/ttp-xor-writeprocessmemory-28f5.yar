rule TTP_XOR_WriteProcessMemory_28f5 {
  strings:
    $key_28f5 = { 7f 87 [2] 4d a5 [2] 4b 90 [2] 65 90 [2] 5a 8c }

  condition:
    any of them
}