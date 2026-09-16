rule TTP_XOR_WriteProcessMemory_6d2b {
  strings:
    $key_6d2b = { 3a 59 [2] 08 7b [2] 0e 4e [2] 20 4e [2] 1f 52 }

  condition:
    any of them
}