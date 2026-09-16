rule TTP_XOR_WriteProcessMemory_1a41 {
  strings:
    $key_1a41 = { 4d 33 [2] 7f 11 [2] 79 24 [2] 57 24 [2] 68 38 }

  condition:
    any of them
}