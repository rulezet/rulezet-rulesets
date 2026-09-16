rule TTP_XOR_WriteProcessMemory_4d19 {
  strings:
    $key_4d19 = { 1a 6b [2] 28 49 [2] 2e 7c [2] 00 7c [2] 3f 60 }

  condition:
    any of them
}