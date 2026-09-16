rule TTP_XOR_WriteProcessMemory_482b {
  strings:
    $key_482b = { 1f 59 [2] 2d 7b [2] 2b 4e [2] 05 4e [2] 3a 52 }

  condition:
    any of them
}