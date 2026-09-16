rule TTP_XOR_WriteProcessMemory_1508 {
  strings:
    $key_1508 = { 42 7a [2] 70 58 [2] 76 6d [2] 58 6d [2] 67 71 }

  condition:
    any of them
}