rule TTP_XOR_WriteProcessMemory_4d21 {
  strings:
    $key_4d21 = { 1a 53 [2] 28 71 [2] 2e 44 [2] 00 44 [2] 3f 58 }

  condition:
    any of them
}