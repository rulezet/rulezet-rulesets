rule TTP_XOR_WriteProcessMemory_6672 {
  strings:
    $key_6672 = { 31 00 [2] 03 22 [2] 05 17 [2] 2b 17 [2] 14 0b }

  condition:
    any of them
}