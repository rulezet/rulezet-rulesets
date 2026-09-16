rule TTP_XOR_WriteProcessMemory_0e00 {
  strings:
    $key_0e00 = { 59 72 [2] 6b 50 [2] 6d 65 [2] 43 65 [2] 7c 79 }

  condition:
    any of them
}