rule TTP_XOR_WriteProcessMemory_0f50 {
  strings:
    $key_0f50 = { 58 22 [2] 6a 00 [2] 6c 35 [2] 42 35 [2] 7d 29 }

  condition:
    any of them
}