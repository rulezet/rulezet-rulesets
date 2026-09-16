rule TTP_XOR_WriteProcessMemory_f525 {
  strings:
    $key_f525 = { a2 57 [2] 90 75 [2] 96 40 [2] b8 40 [2] 87 5c }

  condition:
    any of them
}