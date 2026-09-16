rule TTP_XOR_WriteProcessMemory_6569 {
  strings:
    $key_6569 = { 32 1b [2] 00 39 [2] 06 0c [2] 28 0c [2] 17 10 }

  condition:
    any of them
}