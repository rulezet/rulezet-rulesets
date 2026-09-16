rule TTP_XOR_WriteProcessMemory_6339 {
  strings:
    $key_6339 = { 34 4b [2] 06 69 [2] 00 5c [2] 2e 5c [2] 11 40 }

  condition:
    any of them
}