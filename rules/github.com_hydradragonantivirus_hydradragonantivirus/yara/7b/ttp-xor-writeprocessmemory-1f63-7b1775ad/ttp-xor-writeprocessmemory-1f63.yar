rule TTP_XOR_WriteProcessMemory_1f63 {
  strings:
    $key_1f63 = { 48 11 [2] 7a 33 [2] 7c 06 [2] 52 06 [2] 6d 1a }

  condition:
    any of them
}