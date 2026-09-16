rule TTP_XOR_WriteProcessMemory_1575 {
  strings:
    $key_1575 = { 42 07 [2] 70 25 [2] 76 10 [2] 58 10 [2] 67 0c }

  condition:
    any of them
}