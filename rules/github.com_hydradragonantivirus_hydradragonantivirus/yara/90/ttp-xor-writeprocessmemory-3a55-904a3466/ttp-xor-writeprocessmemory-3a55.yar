rule TTP_XOR_WriteProcessMemory_3a55 {
  strings:
    $key_3a55 = { 6d 27 [2] 5f 05 [2] 59 30 [2] 77 30 [2] 48 2c }

  condition:
    any of them
}