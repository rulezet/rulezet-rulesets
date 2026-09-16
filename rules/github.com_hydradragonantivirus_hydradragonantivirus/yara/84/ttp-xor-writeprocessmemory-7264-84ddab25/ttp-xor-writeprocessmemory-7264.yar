rule TTP_XOR_WriteProcessMemory_7264 {
  strings:
    $key_7264 = { 25 16 [2] 17 34 [2] 11 01 [2] 3f 01 [2] 00 1d }

  condition:
    any of them
}