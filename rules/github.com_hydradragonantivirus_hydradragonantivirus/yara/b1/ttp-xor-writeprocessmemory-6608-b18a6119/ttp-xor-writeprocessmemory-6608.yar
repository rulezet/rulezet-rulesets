rule TTP_XOR_WriteProcessMemory_6608 {
  strings:
    $key_6608 = { 31 7a [2] 03 58 [2] 05 6d [2] 2b 6d [2] 14 71 }

  condition:
    any of them
}