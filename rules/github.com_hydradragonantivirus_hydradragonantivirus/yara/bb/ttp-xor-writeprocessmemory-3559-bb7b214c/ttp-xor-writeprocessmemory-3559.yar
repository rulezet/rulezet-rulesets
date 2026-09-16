rule TTP_XOR_WriteProcessMemory_3559 {
  strings:
    $key_3559 = { 62 2b [2] 50 09 [2] 56 3c [2] 78 3c [2] 47 20 }

  condition:
    any of them
}