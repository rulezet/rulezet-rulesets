rule TTP_XOR_WriteProcessMemory_7309 {
  strings:
    $key_7309 = { 24 7b [2] 16 59 [2] 10 6c [2] 3e 6c [2] 01 70 }

  condition:
    any of them
}