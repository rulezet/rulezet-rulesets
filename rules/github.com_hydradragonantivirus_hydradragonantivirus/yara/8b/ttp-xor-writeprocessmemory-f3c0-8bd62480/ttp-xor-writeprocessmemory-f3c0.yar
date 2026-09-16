rule TTP_XOR_WriteProcessMemory_f3c0 {
  strings:
    $key_f3c0 = { a4 b2 [2] 96 90 [2] 90 a5 [2] be a5 [2] 81 b9 }

  condition:
    any of them
}