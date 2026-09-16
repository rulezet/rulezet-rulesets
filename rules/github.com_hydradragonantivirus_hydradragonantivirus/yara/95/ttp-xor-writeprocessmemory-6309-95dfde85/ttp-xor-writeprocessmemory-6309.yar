rule TTP_XOR_WriteProcessMemory_6309 {
  strings:
    $key_6309 = { 34 7b [2] 06 59 [2] 00 6c [2] 2e 6c [2] 11 70 }

  condition:
    any of them
}