rule TTP_XOR_WriteProcessMemory_6669 {
  strings:
    $key_6669 = { 31 1b [2] 03 39 [2] 05 0c [2] 2b 0c [2] 14 10 }

  condition:
    any of them
}