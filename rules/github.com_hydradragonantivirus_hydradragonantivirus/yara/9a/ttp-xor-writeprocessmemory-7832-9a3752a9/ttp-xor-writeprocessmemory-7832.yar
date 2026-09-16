rule TTP_XOR_WriteProcessMemory_7832 {
  strings:
    $key_7832 = { 2f 40 [2] 1d 62 [2] 1b 57 [2] 35 57 [2] 0a 4b }

  condition:
    any of them
}