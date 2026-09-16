rule TTP_XOR_WriteProcessMemory_0850 {
  strings:
    $key_0850 = { 5f 22 [2] 6d 00 [2] 6b 35 [2] 45 35 [2] 7a 29 }

  condition:
    any of them
}