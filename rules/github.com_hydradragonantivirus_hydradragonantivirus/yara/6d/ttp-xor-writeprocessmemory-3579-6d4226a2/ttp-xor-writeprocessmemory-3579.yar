rule TTP_XOR_WriteProcessMemory_3579 {
  strings:
    $key_3579 = { 62 0b [2] 50 29 [2] 56 1c [2] 78 1c [2] 47 00 }

  condition:
    any of them
}