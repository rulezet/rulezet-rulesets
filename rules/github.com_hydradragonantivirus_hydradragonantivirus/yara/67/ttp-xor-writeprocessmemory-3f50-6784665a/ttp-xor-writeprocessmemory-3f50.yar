rule TTP_XOR_WriteProcessMemory_3f50 {
  strings:
    $key_3f50 = { 68 22 [2] 5a 00 [2] 5c 35 [2] 72 35 [2] 4d 29 }

  condition:
    any of them
}