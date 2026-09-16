rule TTP_XOR_WriteProcessMemory_5632 {
  strings:
    $key_5632 = { 01 40 [2] 33 62 [2] 35 57 [2] 1b 57 [2] 24 4b }

  condition:
    any of them
}