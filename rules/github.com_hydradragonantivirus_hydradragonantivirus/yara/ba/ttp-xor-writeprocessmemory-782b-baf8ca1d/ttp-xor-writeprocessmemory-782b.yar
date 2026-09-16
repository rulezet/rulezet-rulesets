rule TTP_XOR_WriteProcessMemory_782b {
  strings:
    $key_782b = { 2f 59 [2] 1d 7b [2] 1b 4e [2] 35 4e [2] 0a 52 }

  condition:
    any of them
}