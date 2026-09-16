rule TTP_XOR_WriteProcessMemory_3a1b {
  strings:
    $key_3a1b = { 6d 69 [2] 5f 4b [2] 59 7e [2] 77 7e [2] 48 62 }

  condition:
    any of them
}