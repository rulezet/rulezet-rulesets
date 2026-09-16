rule TTP_XOR_WriteProcessMemory_0863 {
  strings:
    $key_0863 = { 5f 11 [2] 6d 33 [2] 6b 06 [2] 45 06 [2] 7a 1a }

  condition:
    any of them
}