rule TTP_XOR_WriteProcessMemory_4de9 {
  strings:
    $key_4de9 = { 1a 9b [2] 28 b9 [2] 2e 8c [2] 00 8c [2] 3f 90 }

  condition:
    any of them
}