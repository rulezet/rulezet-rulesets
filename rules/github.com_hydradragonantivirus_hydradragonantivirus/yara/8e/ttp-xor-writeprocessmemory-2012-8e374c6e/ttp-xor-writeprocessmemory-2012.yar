rule TTP_XOR_WriteProcessMemory_2012 {
  strings:
    $key_2012 = { 77 60 [2] 45 42 [2] 43 77 [2] 6d 77 [2] 52 6b }

  condition:
    any of them
}