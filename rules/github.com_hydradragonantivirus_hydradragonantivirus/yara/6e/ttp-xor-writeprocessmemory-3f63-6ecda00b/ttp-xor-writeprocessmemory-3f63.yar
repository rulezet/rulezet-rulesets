rule TTP_XOR_WriteProcessMemory_3f63 {
  strings:
    $key_3f63 = { 68 11 [2] 5a 33 [2] 5c 06 [2] 72 06 [2] 4d 1a }

  condition:
    any of them
}