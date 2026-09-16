rule TTP_XOR_WriteProcessMemory_3c1b {
  strings:
    $key_3c1b = { 6b 69 [2] 59 4b [2] 5f 7e [2] 71 7e [2] 4e 62 }

  condition:
    any of them
}