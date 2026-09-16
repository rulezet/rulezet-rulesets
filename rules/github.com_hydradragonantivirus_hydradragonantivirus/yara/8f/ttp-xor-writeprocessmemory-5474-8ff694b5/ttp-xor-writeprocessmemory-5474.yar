rule TTP_XOR_WriteProcessMemory_5474 {
  strings:
    $key_5474 = { 03 06 [2] 31 24 [2] 37 11 [2] 19 11 [2] 26 0d }

  condition:
    any of them
}