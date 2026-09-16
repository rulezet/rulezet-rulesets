rule TTP_XOR_WriteProcessMemory_2059 {
  strings:
    $key_2059 = { 77 2b [2] 45 09 [2] 43 3c [2] 6d 3c [2] 52 20 }

  condition:
    any of them
}