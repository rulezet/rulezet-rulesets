rule TTP_XOR_WriteProcessMemory_5359 {
  strings:
    $key_5359 = { 04 2b [2] 36 09 [2] 30 3c [2] 1e 3c [2] 21 20 }

  condition:
    any of them
}