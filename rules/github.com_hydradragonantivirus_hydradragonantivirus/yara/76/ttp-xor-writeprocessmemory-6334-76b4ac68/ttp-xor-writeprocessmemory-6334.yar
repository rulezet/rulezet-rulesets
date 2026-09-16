rule TTP_XOR_WriteProcessMemory_6334 {
  strings:
    $key_6334 = { 34 46 [2] 06 64 [2] 00 51 [2] 2e 51 [2] 11 4d }

  condition:
    any of them
}