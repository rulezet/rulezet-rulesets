rule TTP_XOR_WriteProcessMemory_6365 {
  strings:
    $key_6365 = { 34 17 [2] 06 35 [2] 00 00 [2] 2e 00 [2] 11 1c }

  condition:
    any of them
}