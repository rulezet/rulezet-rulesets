rule TTP_XOR_WriteProcessMemory_f315 {
  strings:
    $key_f315 = { a4 67 [2] 96 45 [2] 90 70 [2] be 70 [2] 81 6c }

  condition:
    any of them
}