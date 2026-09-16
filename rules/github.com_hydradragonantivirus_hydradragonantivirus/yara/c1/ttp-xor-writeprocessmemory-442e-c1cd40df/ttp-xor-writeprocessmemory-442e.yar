rule TTP_XOR_WriteProcessMemory_442e {
  strings:
    $key_442e = { 13 5c [2] 21 7e [2] 27 4b [2] 09 4b [2] 36 57 }

  condition:
    any of them
}