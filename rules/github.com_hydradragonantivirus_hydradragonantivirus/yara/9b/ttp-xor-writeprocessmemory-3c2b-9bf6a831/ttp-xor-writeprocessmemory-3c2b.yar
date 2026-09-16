rule TTP_XOR_WriteProcessMemory_3c2b {
  strings:
    $key_3c2b = { 6b 59 [2] 59 7b [2] 5f 4e [2] 71 4e [2] 4e 52 }

  condition:
    any of them
}