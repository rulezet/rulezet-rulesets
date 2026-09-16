rule TTP_XOR_WriteProcessMemory_7554 {
  strings:
    $key_7554 = { 22 26 [2] 10 04 [2] 16 31 [2] 38 31 [2] 07 2d }

  condition:
    any of them
}