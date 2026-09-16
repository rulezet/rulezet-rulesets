rule TTP_XOR_WriteProcessMemory_666b {
  strings:
    $key_666b = { 31 19 [2] 03 3b [2] 05 0e [2] 2b 0e [2] 14 12 }

  condition:
    any of them
}