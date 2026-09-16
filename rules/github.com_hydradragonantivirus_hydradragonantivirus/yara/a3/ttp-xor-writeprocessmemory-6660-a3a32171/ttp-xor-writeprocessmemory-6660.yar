rule TTP_XOR_WriteProcessMemory_6660 {
  strings:
    $key_6660 = { 31 12 [2] 03 30 [2] 05 05 [2] 2b 05 [2] 14 19 }

  condition:
    any of them
}