rule TTP_XOR_WriteProcessMemory_4a63 {
  strings:
    $key_4a63 = { 1d 11 [2] 2f 33 [2] 29 06 [2] 07 06 [2] 38 1a }

  condition:
    any of them
}