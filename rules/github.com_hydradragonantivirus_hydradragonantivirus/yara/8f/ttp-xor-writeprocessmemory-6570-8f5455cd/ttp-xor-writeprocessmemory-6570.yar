rule TTP_XOR_WriteProcessMemory_6570 {
  strings:
    $key_6570 = { 32 02 [2] 00 20 [2] 06 15 [2] 28 15 [2] 17 09 }

  condition:
    any of them
}