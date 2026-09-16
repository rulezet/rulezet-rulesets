rule TTP_XOR_WriteProcessMemory_632b {
  strings:
    $key_632b = { 34 59 [2] 06 7b [2] 00 4e [2] 2e 4e [2] 11 52 }

  condition:
    any of them
}