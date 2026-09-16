rule TTP_XOR_WriteProcessMemory_4c64 {
  strings:
    $key_4c64 = { 1b 16 [2] 29 34 [2] 2f 01 [2] 01 01 [2] 3e 1d }

  condition:
    any of them
}