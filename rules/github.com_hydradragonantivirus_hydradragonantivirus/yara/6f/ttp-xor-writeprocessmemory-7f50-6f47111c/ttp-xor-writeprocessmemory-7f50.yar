rule TTP_XOR_WriteProcessMemory_7f50 {
  strings:
    $key_7f50 = { 28 22 [2] 1a 00 [2] 1c 35 [2] 32 35 [2] 0d 29 }

  condition:
    any of them
}