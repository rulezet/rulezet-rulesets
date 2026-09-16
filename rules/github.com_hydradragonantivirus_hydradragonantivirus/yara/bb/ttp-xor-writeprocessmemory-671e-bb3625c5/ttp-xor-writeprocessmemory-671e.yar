rule TTP_XOR_WriteProcessMemory_671e {
  strings:
    $key_671e = { 30 6c [2] 02 4e [2] 04 7b [2] 2a 7b [2] 15 67 }

  condition:
    any of them
}