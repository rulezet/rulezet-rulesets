rule TTP_XOR_WriteProcessMemory_5071 {
  strings:
    $key_5071 = { 07 03 [2] 35 21 [2] 33 14 [2] 1d 14 [2] 22 08 }

  condition:
    any of them
}