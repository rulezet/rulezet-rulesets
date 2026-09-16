rule TTP_XOR_WriteProcessMemory_5470 {
  strings:
    $key_5470 = { 03 02 [2] 31 20 [2] 37 15 [2] 19 15 [2] 26 09 }

  condition:
    any of them
}