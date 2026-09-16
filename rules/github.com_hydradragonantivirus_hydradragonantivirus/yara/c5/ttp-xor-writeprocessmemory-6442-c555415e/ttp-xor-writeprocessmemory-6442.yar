rule TTP_XOR_WriteProcessMemory_6442 {
  strings:
    $key_6442 = { 33 30 [2] 01 12 [2] 07 27 [2] 29 27 [2] 16 3b }

  condition:
    any of them
}