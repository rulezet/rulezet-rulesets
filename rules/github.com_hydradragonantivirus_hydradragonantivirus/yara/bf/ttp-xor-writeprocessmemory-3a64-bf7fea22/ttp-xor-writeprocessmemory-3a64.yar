rule TTP_XOR_WriteProcessMemory_3a64 {
  strings:
    $key_3a64 = { 6d 16 [2] 5f 34 [2] 59 01 [2] 77 01 [2] 48 1d }

  condition:
    any of them
}