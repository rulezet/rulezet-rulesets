rule TTP_XOR_WriteProcessMemory_3c5b {
  strings:
    $key_3c5b = { 6b 29 [2] 59 0b [2] 5f 3e [2] 71 3e [2] 4e 22 }

  condition:
    any of them
}