rule TTP_XOR_WriteProcessMemory_4d59 {
  strings:
    $key_4d59 = { 1a 2b [2] 28 09 [2] 2e 3c [2] 00 3c [2] 3f 20 }

  condition:
    any of them
}