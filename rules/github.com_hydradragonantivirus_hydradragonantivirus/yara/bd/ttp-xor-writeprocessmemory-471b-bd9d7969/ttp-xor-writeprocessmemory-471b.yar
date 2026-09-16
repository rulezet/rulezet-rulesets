rule TTP_XOR_WriteProcessMemory_471b {
  strings:
    $key_471b = { 10 69 [2] 22 4b [2] 24 7e [2] 0a 7e [2] 35 62 }

  condition:
    any of them
}