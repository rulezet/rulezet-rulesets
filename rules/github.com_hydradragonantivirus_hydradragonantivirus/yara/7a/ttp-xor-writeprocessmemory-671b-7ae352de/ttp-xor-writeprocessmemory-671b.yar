rule TTP_XOR_WriteProcessMemory_671b {
  strings:
    $key_671b = { 30 69 [2] 02 4b [2] 04 7e [2] 2a 7e [2] 15 62 }

  condition:
    any of them
}