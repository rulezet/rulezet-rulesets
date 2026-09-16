rule TTP_XOR_WriteProcessMemory_f332 {
  strings:
    $key_f332 = { a4 40 [2] 96 62 [2] 90 57 [2] be 57 [2] 81 4b }

  condition:
    any of them
}