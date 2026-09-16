rule TTP_XOR_WriteProcessMemory_3c63 {
  strings:
    $key_3c63 = { 6b 11 [2] 59 33 [2] 5f 06 [2] 71 06 [2] 4e 1a }

  condition:
    any of them
}