rule TTP_XOR_WriteProcessMemory_5c64 {
  strings:
    $key_5c64 = { 0b 16 [2] 39 34 [2] 3f 01 [2] 11 01 [2] 2e 1d }

  condition:
    any of them
}