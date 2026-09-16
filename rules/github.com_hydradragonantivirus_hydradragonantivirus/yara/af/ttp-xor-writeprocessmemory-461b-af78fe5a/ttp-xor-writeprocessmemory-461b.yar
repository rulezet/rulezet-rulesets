rule TTP_XOR_WriteProcessMemory_461b {
  strings:
    $key_461b = { 11 69 [2] 23 4b [2] 25 7e [2] 0b 7e [2] 34 62 }

  condition:
    any of them
}