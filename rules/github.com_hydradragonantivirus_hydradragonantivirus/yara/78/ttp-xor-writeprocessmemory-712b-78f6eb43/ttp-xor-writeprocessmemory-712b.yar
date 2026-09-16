rule TTP_XOR_WriteProcessMemory_712b {
  strings:
    $key_712b = { 26 59 [2] 14 7b [2] 12 4e [2] 3c 4e [2] 03 52 }

  condition:
    any of them
}