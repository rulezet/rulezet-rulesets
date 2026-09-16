rule TTP_XOR_WriteProcessMemory_6554 {
  strings:
    $key_6554 = { 32 26 [2] 00 04 [2] 06 31 [2] 28 31 [2] 17 2d }

  condition:
    any of them
}