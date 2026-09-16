rule TTP_XOR_WriteProcessMemory_f320 {
  strings:
    $key_f320 = { a4 52 [2] 96 70 [2] 90 45 [2] be 45 [2] 81 59 }

  condition:
    any of them
}