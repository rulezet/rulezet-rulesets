rule TTP_XOR_WriteProcessMemory_6860 {
  strings:
    $key_6860 = { 3f 12 [2] 0d 30 [2] 0b 05 [2] 25 05 [2] 1a 19 }

  condition:
    any of them
}