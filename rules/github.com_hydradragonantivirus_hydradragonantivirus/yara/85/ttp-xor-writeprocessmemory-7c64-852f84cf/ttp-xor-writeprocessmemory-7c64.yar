rule TTP_XOR_WriteProcessMemory_7c64 {
  strings:
    $key_7c64 = { 2b 16 [2] 19 34 [2] 1f 01 [2] 31 01 [2] 0e 1d }

  condition:
    any of them
}