rule TTP_XOR_WriteProcessMemory_6665 {
  strings:
    $key_6665 = { 31 17 [2] 03 35 [2] 05 00 [2] 2b 00 [2] 14 1c }

  condition:
    any of them
}