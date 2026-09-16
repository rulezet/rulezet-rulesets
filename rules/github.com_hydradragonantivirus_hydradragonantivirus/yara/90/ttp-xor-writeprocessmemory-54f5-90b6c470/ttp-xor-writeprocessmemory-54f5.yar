rule TTP_XOR_WriteProcessMemory_54f5 {
  strings:
    $key_54f5 = { 03 87 [2] 31 a5 [2] 37 90 [2] 19 90 [2] 26 8c }

  condition:
    any of them
}