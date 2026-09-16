rule TTP_XOR_WriteProcessMemory_5672 {
  strings:
    $key_5672 = { 01 00 [2] 33 22 [2] 35 17 [2] 1b 17 [2] 24 0b }

  condition:
    any of them
}