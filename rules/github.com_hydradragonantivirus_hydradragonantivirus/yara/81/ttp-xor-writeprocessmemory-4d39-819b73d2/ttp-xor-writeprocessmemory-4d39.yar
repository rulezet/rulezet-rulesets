rule TTP_XOR_WriteProcessMemory_4d39 {
  strings:
    $key_4d39 = { 1a 4b [2] 28 69 [2] 2e 5c [2] 00 5c [2] 3f 40 }

  condition:
    any of them
}