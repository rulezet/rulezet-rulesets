rule TTP_XOR_WriteProcessMemory_591b {
  strings:
    $key_591b = { 0e 69 [2] 3c 4b [2] 3a 7e [2] 14 7e [2] 2b 62 }

  condition:
    any of them
}