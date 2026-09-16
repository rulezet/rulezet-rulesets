rule TTP_XOR_WriteProcessMemory_f351 {
  strings:
    $key_f351 = { a4 23 [2] 96 01 [2] 90 34 [2] be 34 [2] 81 28 }

  condition:
    any of them
}