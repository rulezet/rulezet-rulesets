rule TTP_XOR_WriteProcessMemory_3c22 {
  strings:
    $key_3c22 = { 6b 50 [2] 59 72 [2] 5f 47 [2] 71 47 [2] 4e 5b }

  condition:
    any of them
}