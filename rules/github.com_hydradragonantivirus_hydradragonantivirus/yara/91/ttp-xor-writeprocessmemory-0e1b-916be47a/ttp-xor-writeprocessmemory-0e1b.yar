rule TTP_XOR_WriteProcessMemory_0e1b {
  strings:
    $key_0e1b = { 59 69 [2] 6b 4b [2] 6d 7e [2] 43 7e [2] 7c 62 }

  condition:
    any of them
}