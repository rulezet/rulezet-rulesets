rule TTP_XOR_WriteProcessMemory_3065 {
  strings:
    $key_3065 = { 67 17 [2] 55 35 [2] 53 00 [2] 7d 00 [2] 42 1c }

  condition:
    any of them
}