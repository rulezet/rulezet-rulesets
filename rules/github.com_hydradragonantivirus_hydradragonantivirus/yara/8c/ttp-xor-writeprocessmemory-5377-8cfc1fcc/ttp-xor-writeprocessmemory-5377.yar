rule TTP_XOR_WriteProcessMemory_5377 {
  strings:
    $key_5377 = { 04 05 [2] 36 27 [2] 30 12 [2] 1e 12 [2] 21 0e }

  condition:
    any of them
}