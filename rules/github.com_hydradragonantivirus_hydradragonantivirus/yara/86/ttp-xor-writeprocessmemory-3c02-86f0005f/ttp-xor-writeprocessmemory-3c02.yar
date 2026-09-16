rule TTP_XOR_WriteProcessMemory_3c02 {
  strings:
    $key_3c02 = { 6b 70 [2] 59 52 [2] 5f 67 [2] 71 67 [2] 4e 7b }

  condition:
    any of them
}