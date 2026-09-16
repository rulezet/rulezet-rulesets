rule TTP_XOR_WriteProcessMemory_3c41 {
  strings:
    $key_3c41 = { 6b 33 [2] 59 11 [2] 5f 24 [2] 71 24 [2] 4e 38 }

  condition:
    any of them
}