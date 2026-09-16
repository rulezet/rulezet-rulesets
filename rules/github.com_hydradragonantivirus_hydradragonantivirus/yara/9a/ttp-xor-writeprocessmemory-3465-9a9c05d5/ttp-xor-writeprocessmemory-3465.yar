rule TTP_XOR_WriteProcessMemory_3465 {
  strings:
    $key_3465 = { 63 17 [2] 51 35 [2] 57 00 [2] 79 00 [2] 46 1c }

  condition:
    any of them
}