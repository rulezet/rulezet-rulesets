rule TTP_XOR_WriteProcessMemory_2579 {
  strings:
    $key_2579 = { 72 0b [2] 40 29 [2] 46 1c [2] 68 1c [2] 57 00 }

  condition:
    any of them
}