rule TTP_XOR_WriteProcessMemory_7e06 {
  strings:
    $key_7e06 = { 29 74 [2] 1b 56 [2] 1d 63 [2] 33 63 [2] 0c 7f }

  condition:
    any of them
}