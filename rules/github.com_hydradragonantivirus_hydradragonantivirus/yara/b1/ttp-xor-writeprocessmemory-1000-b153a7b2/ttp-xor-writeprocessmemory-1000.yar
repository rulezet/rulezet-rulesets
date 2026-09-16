rule TTP_XOR_WriteProcessMemory_1000 {
  strings:
    $key_1000 = { 47 72 [2] 75 50 [2] 73 65 [2] 5d 65 [2] 62 79 }

  condition:
    any of them
}