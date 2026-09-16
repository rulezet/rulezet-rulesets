rule TTP_XOR_WriteProcessMemory_43f5 {
  strings:
    $key_43f5 = { 14 87 [2] 26 a5 [2] 20 90 [2] 0e 90 [2] 31 8c }

  condition:
    any of them
}