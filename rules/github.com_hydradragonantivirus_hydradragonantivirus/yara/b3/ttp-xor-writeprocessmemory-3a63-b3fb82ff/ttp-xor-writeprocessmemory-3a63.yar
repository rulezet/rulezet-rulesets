rule TTP_XOR_WriteProcessMemory_3a63 {
  strings:
    $key_3a63 = { 6d 11 [2] 5f 33 [2] 59 06 [2] 77 06 [2] 48 1a }

  condition:
    any of them
}