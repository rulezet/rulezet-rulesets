rule TTP_XOR_WriteProcessMemory_551b {
  strings:
    $key_551b = { 02 69 [2] 30 4b [2] 36 7e [2] 18 7e [2] 27 62 }

  condition:
    any of them
}