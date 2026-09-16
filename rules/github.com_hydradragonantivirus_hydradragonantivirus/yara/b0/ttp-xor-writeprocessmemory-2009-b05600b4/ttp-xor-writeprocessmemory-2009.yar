rule TTP_XOR_WriteProcessMemory_2009 {
  strings:
    $key_2009 = { 77 7b [2] 45 59 [2] 43 6c [2] 6d 6c [2] 52 70 }

  condition:
    any of them
}