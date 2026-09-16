rule TTP_XOR_WriteProcessMemory_4339 {
  strings:
    $key_4339 = { 14 4b [2] 26 69 [2] 20 5c [2] 0e 5c [2] 31 40 }

  condition:
    any of them
}