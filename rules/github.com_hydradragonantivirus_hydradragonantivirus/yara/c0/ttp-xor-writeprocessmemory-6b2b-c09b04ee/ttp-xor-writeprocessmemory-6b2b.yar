rule TTP_XOR_WriteProcessMemory_6b2b {
  strings:
    $key_6b2b = { 3c 59 [2] 0e 7b [2] 08 4e [2] 26 4e [2] 19 52 }

  condition:
    any of them
}