rule TTP_XOR_WriteProcessMemory_f515 {
  strings:
    $key_f515 = { a2 67 [2] 90 45 [2] 96 70 [2] b8 70 [2] 87 6c }

  condition:
    any of them
}