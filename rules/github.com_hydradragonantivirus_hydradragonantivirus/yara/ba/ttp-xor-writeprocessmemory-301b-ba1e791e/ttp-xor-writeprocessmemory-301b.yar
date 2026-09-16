rule TTP_XOR_WriteProcessMemory_301b {
  strings:
    $key_301b = { 67 69 [2] 55 4b [2] 53 7e [2] 7d 7e [2] 42 62 }

  condition:
    any of them
}