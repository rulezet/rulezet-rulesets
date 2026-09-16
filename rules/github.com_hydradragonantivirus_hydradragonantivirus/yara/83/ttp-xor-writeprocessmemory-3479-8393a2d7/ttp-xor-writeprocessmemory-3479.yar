rule TTP_XOR_WriteProcessMemory_3479 {
  strings:
    $key_3479 = { 63 0b [2] 51 29 [2] 57 1c [2] 79 1c [2] 46 00 }

  condition:
    any of them
}