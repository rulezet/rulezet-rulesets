rule TTP_XOR_WriteProcessMemory_6d63 {
  strings:
    $key_6d63 = { 3a 11 [2] 08 33 [2] 0e 06 [2] 20 06 [2] 1f 1a }

  condition:
    any of them
}