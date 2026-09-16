rule TTP_XOR_WriteProcessMemory_2f63 {
  strings:
    $key_2f63 = { 78 11 [2] 4a 33 [2] 4c 06 [2] 62 06 [2] 5d 1a }

  condition:
    any of them
}