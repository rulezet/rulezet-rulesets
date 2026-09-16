rule TTP_XOR_WriteProcessMemory_6479 {
  strings:
    $key_6479 = { 33 0b [2] 01 29 [2] 07 1c [2] 29 1c [2] 16 00 }

  condition:
    any of them
}