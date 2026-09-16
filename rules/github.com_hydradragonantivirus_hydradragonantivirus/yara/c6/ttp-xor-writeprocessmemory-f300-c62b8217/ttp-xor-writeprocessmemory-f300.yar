rule TTP_XOR_WriteProcessMemory_f300 {
  strings:
    $key_f300 = { a4 72 [2] 96 50 [2] 90 65 [2] be 65 [2] 81 79 }

  condition:
    any of them
}