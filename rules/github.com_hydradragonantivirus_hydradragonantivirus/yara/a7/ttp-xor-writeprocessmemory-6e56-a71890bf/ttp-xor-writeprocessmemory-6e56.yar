rule TTP_XOR_WriteProcessMemory_6e56 {
  strings:
    $key_6e56 = { 39 24 [2] 0b 06 [2] 0d 33 [2] 23 33 [2] 1c 2f }

  condition:
    any of them
}