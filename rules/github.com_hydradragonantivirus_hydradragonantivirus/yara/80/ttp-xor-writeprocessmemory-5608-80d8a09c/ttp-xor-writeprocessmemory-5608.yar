rule TTP_XOR_WriteProcessMemory_5608 {
  strings:
    $key_5608 = { 01 7a [2] 33 58 [2] 35 6d [2] 1b 6d [2] 24 71 }

  condition:
    any of them
}