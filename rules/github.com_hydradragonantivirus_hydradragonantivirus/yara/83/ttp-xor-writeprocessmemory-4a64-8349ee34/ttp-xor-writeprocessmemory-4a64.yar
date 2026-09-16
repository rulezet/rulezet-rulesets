rule TTP_XOR_WriteProcessMemory_4a64 {
  strings:
    $key_4a64 = { 1d 16 [2] 2f 34 [2] 29 01 [2] 07 01 [2] 38 1d }

  condition:
    any of them
}