rule TTP_XOR_WriteProcessMemory_7221 {
  strings:
    $key_7221 = { 25 53 [2] 17 71 [2] 11 44 [2] 3f 44 [2] 00 58 }

  condition:
    any of them
}