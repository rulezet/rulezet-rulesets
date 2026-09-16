rule TTP_XOR_WriteProcessMemory_5074 {
  strings:
    $key_5074 = { 07 06 [2] 35 24 [2] 33 11 [2] 1d 11 [2] 22 0d }

  condition:
    any of them
}