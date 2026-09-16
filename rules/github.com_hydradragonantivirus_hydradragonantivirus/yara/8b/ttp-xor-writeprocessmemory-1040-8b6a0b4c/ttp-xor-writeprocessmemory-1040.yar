rule TTP_XOR_WriteProcessMemory_1040 {
  strings:
    $key_1040 = { 47 32 [2] 75 10 [2] 73 25 [2] 5d 25 [2] 62 39 }

  condition:
    any of them
}