rule TTP_XOR_WriteProcessMemory_4065 {
  strings:
    $key_4065 = { 17 17 [2] 25 35 [2] 23 00 [2] 0d 00 [2] 32 1c }

  condition:
    any of them
}