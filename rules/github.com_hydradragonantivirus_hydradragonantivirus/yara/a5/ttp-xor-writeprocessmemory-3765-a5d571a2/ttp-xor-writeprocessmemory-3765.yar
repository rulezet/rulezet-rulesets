rule TTP_XOR_WriteProcessMemory_3765 {
  strings:
    $key_3765 = { 60 17 [2] 52 35 [2] 54 00 [2] 7a 00 [2] 45 1c }

  condition:
    any of them
}