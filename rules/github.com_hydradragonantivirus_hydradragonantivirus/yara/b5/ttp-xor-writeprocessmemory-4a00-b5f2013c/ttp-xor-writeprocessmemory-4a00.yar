rule TTP_XOR_WriteProcessMemory_4a00 {
  strings:
    $key_4a00 = { 1d 72 [2] 2f 50 [2] 29 65 [2] 07 65 [2] 38 79 }

  condition:
    any of them
}