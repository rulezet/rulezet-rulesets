rule TTP_XOR_WriteProcessMemory_6771 {
  strings:
    $key_6771 = { 30 03 [2] 02 21 [2] 04 14 [2] 2a 14 [2] 15 08 }

  condition:
    any of them
}