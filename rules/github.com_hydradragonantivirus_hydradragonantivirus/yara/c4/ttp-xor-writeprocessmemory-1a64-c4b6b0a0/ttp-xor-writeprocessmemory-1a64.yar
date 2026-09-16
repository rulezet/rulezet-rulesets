rule TTP_XOR_WriteProcessMemory_1a64 {
  strings:
    $key_1a64 = { 4d 16 [2] 7f 34 [2] 79 01 [2] 57 01 [2] 68 1d }

  condition:
    any of them
}