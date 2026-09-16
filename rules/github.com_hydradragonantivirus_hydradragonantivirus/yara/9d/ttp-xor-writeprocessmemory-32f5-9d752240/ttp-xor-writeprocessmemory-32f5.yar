rule TTP_XOR_WriteProcessMemory_32f5 {
  strings:
    $key_32f5 = { 65 87 [2] 57 a5 [2] 51 90 [2] 7f 90 [2] 40 8c }

  condition:
    any of them
}