rule TTP_XOR_WriteProcessMemory_6529 {
  strings:
    $key_6529 = { 32 5b [2] 00 79 [2] 06 4c [2] 28 4c [2] 17 50 }

  condition:
    any of them
}