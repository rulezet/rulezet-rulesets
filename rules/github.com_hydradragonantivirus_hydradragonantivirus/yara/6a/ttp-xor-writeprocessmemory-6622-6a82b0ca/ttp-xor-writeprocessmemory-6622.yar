rule TTP_XOR_WriteProcessMemory_6622 {
  strings:
    $key_6622 = { 31 50 [2] 03 72 [2] 05 47 [2] 2b 47 [2] 14 5b }

  condition:
    any of them
}