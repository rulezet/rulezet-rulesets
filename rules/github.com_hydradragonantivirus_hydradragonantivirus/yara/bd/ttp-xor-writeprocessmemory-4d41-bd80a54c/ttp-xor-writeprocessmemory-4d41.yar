rule TTP_XOR_WriteProcessMemory_4d41 {
  strings:
    $key_4d41 = { 1a 33 [2] 28 11 [2] 2e 24 [2] 00 24 [2] 3f 38 }

  condition:
    any of them
}